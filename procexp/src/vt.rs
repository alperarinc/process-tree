//! VirusTotal lookups: background hashing + rate-limited query queue with a persistent cache.
//! Only SHA-256 hashes leave the machine. The API key is never logged or written to the cache.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Debug, PartialEq)]
pub enum VtState {
    Pending,
    Querying,
    Unknown,
    Done { malicious: u32, total: u32 },
    Error(String),
}

impl VtState {
    pub fn text(&self) -> String {
        match self {
            VtState::Pending => "bekliyor".into(),
            VtState::Querying => "sorgulanıyor".into(),
            VtState::Unknown => "bilinmiyor".into(),
            VtState::Done { malicious, total } => format!("{malicious}/{total}"),
            VtState::Error(_) => "hata".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum VtOutcome {
    Done { malicious: u32, total: u32 },
    Unknown,
    RateLimited,
    BadKey,
    Error(String),
}

pub fn parse_response(status: u16, body: &str) -> VtOutcome {
    match status {
        200 => {
            let v: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(e) => return VtOutcome::Error(format!("yanıt çözülemedi: {e}")),
            };
            let stats = &v["data"]["attributes"]["last_analysis_stats"];
            let n = |k: &str| stats[k].as_u64().unwrap_or(0) as u32;
            if !stats.is_object() {
                return VtOutcome::Error("yanıtta analiz özeti yok".into());
            }
            VtOutcome::Done { malicious: n("malicious"), total: n("malicious") + n("suspicious") + n("undetected") + n("harmless") }
        }
        404 => VtOutcome::Unknown,
        429 => VtOutcome::RateLimited,
        401 | 403 => VtOutcome::BadKey,
        s => VtOutcome::Error(format!("HTTP {s}")),
    }
}

/// Per-minute (sliding window) and per-UTC-day request budget.
pub struct RateLimiter {
    per_min: u32,
    per_day: u32,
    recent: VecDeque<u64>,
    day: u64,
    day_count: u32,
}

impl RateLimiter {
    pub fn new(per_min: u32, per_day: u32) -> Self {
        Self { per_min, per_day, recent: VecDeque::new(), day: 0, day_count: 0 }
    }

    pub fn try_take(&mut self, now_unix: u64) -> bool {
        while self.recent.front().is_some_and(|&t| t + 60 <= now_unix) {
            self.recent.pop_front();
        }
        let day = now_unix / 86_400;
        if day != self.day {
            self.day = day;
            self.day_count = 0;
        }
        if self.recent.len() as u32 >= self.per_min || self.day_count >= self.per_day {
            return false;
        }
        self.recent.push_back(now_unix);
        self.day_count += 1;
        true
    }
}

pub trait VtHttp: Send {
    fn get(&self, sha256: &str, key: &str) -> Result<(u16, String), String>;
}

pub struct UreqHttp;

impl VtHttp for UreqHttp {
    fn get(&self, sha256: &str, key: &str) -> Result<(u16, String), String> {
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
        let r = agent.get(&format!("https://www.virustotal.com/api/v3/files/{sha256}")).set("x-apikey", key).call();
        match r {
            Ok(resp) | Err(ureq::Error::Status(_, resp)) => {
                let status = resp.status();
                Ok((status, resp.into_string().map_err(|e| e.to_string())?))
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

pub struct VtConfig {
    pub now_unix: Box<dyn Fn() -> u64 + Send>,
    /// Pause after a 429.
    pub rate_pause: Duration,
    /// Delay before retrying after a network error.
    pub retry: Duration,
    /// Re-check interval when only the local limiter blocks.
    pub poll: Duration,
}

impl Default for VtConfig {
    fn default() -> Self {
        Self {
            now_unix: Box::new(|| SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())),
            rate_pause: Duration::from_secs(60),
            retry: Duration::from_secs(300),
            poll: Duration::from_secs(5),
        }
    }
}

pub fn default_cache_path() -> PathBuf {
    crate::settings::app_support_dir().join("vt-cache.json")
}

#[derive(Serialize, Deserialize, Default)]
struct DiskCache {
    /// sha256 -> Some((malicious, total)) or None for "unknown to VirusTotal"
    results: HashMap<String, Option<(u32, u32)>>,
    day: u64,
    day_count: u32,
}

struct Inner {
    queue: VecDeque<PathBuf>,
    states: HashMap<PathBuf, VtState>,
    retry_at: HashMap<PathBuf, Instant>,
    paused_until: Option<Instant>,
    bad_key: bool,
    key: String,
    stop: bool,
    results: HashMap<String, Option<(u32, u32)>>,
    limiter: RateLimiter,
}

struct Shared {
    inner: Mutex<Inner>,
    cv: Condvar,
}

pub struct VtService {
    shared: Arc<Shared>,
}

const BAD_KEY_MSG: &str = "API anahtarı geçersiz";

impl VtService {
    pub fn new(cache_path: PathBuf, http: Box<dyn VtHttp>, key: String, repaint: Box<dyn Fn() + Send>) -> Self {
        Self::with_config(cache_path, http, key, repaint, VtConfig::default())
    }

    pub fn with_config(cache_path: PathBuf, http: Box<dyn VtHttp>, key: String, repaint: Box<dyn Fn() + Send>, cfg: VtConfig) -> Self {
        let disk: DiskCache = std::fs::read(&cache_path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let mut limiter = RateLimiter::new(4, 500);
        limiter.day = disk.day;
        limiter.day_count = disk.day_count;
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                states: HashMap::new(),
                retry_at: HashMap::new(),
                paused_until: None,
                bad_key: false,
                key,
                stop: false,
                results: disk.results,
                limiter,
            }),
            cv: Condvar::new(),
        });
        let sh = shared.clone();
        std::thread::Builder::new()
            .name("virustotal".into())
            .spawn(move || worker(sh, cache_path, http, repaint, cfg))
            .expect("spawn virustotal");
        Self { shared }
    }

    pub fn enqueue(&self, exe: &Path) {
        let mut g = self.shared.inner.lock().unwrap();
        if g.states.contains_key(exe) {
            return;
        }
        let st = if g.bad_key { VtState::Error(BAD_KEY_MSG.into()) } else { VtState::Pending };
        g.states.insert(exe.to_path_buf(), st);
        g.queue.push_back(exe.to_path_buf());
        self.shared.cv.notify_all();
    }

    /// Move an already-queued path to the front (e.g. the row the user selected).
    pub fn prioritize(&self, exe: &Path) {
        let mut g = self.shared.inner.lock().unwrap();
        if let Some(i) = g.queue.iter().position(|p| p == exe) {
            let p = g.queue.remove(i).unwrap();
            g.queue.push_front(p);
            g.retry_at.remove(exe);
            self.shared.cv.notify_all();
        }
    }

    pub fn state(&self, exe: &Path) -> VtState {
        self.shared.inner.lock().unwrap().states.get(exe).cloned().unwrap_or(VtState::Pending)
    }

    /// Replace the key and resume a queue that stopped on a bad key.
    pub fn set_key(&self, key: String) {
        let mut g = self.shared.inner.lock().unwrap();
        g.key = key;
        if g.bad_key {
            g.bad_key = false;
            let Inner { queue, states, .. } = &mut *g;
            for p in queue.iter() {
                states.insert(p.clone(), VtState::Pending);
            }
        }
        self.shared.cv.notify_all();
    }
}

impl Drop for VtService {
    fn drop(&mut self) {
        self.shared.inner.lock().unwrap().stop = true;
        self.shared.cv.notify_all();
    }
}

fn hash_file(path: &Path) -> std::io::Result<(String, (SystemTime, u64))> {
    let mut f = std::fs::File::open(path)?;
    let md = f.metadata()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let hex = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Ok((hex, (md.modified()?, md.len())))
}

fn save_cache(path: &Path, g: &Inner) {
    let d = DiskCache { results: g.results.clone(), day: g.limiter.day, day_count: g.limiter.day_count };
    if let Ok(json) = serde_json::to_vec(&d) {
        let _ = std::fs::write(path, json); // best effort; the cache is an optimisation
    }
}

fn from_cached(r: Option<(u32, u32)>) -> VtState {
    r.map_or(VtState::Unknown, |(malicious, total)| VtState::Done { malicious, total })
}

fn worker(sh: Arc<Shared>, cache_path: PathBuf, http: Box<dyn VtHttp>, repaint: Box<dyn Fn() + Send>, cfg: VtConfig) {
    crate::darwin::set_background_qos();
    let mut file_sha: HashMap<PathBuf, (SystemTime, u64, String)> = HashMap::new();
    let mut g = sh.inner.lock().unwrap();
    loop {
        if g.stop {
            return;
        }
        let now = Instant::now();
        // Decide what to do next, or how long to sleep (None = until notified).
        let mut wait: Option<Duration> = None;
        let mut pick = None;
        if g.bad_key {
            // sleep until set_key
        } else if let Some(t) = g.paused_until.filter(|&t| t > now) {
            wait = Some(t - now);
        } else {
            g.paused_until = None;
            for (i, p) in g.queue.iter().enumerate() {
                match g.retry_at.get(p) {
                    Some(&t) if t > now => wait = Some(wait.map_or(t - now, |w| w.min(t - now))),
                    _ => {
                        pick = Some(i);
                        break;
                    }
                }
            }
        }
        let Some(i) = pick else {
            g = match wait {
                Some(w) => sh.cv.wait_timeout(g, w).unwrap().0,
                None => sh.cv.wait(g).unwrap(),
            };
            continue;
        };
        let path = g.queue[i].clone();
        g.retry_at.remove(&path);
        g.states.insert(path.clone(), VtState::Querying);
        drop(g);
        repaint();

        // Hash outside the lock; unchanged files (path, mtime, size) are not rehashed.
        let hashed = match std::fs::metadata(&path).and_then(|m| Ok((m.modified()?, m.len()))) {
            Ok((mt, sz)) => match file_sha.get(&path) {
                Some((m, s, sha)) if *m == mt && *s == sz => Ok(sha.clone()),
                _ => hash_file(&path).map(|(sha, (mt, sz))| {
                    file_sha.insert(path.clone(), (mt, sz, sha.clone()));
                    sha
                }),
            },
            Err(e) => Err(e),
        };

        g = sh.inner.lock().unwrap();
        let Some(pos) = g.queue.iter().position(|p| *p == path) else { continue };
        let sha = match hashed {
            Ok(s) => s,
            Err(_) => {
                g.queue.remove(pos);
                g.states.insert(path, VtState::Error("okunamadı".into()));
                drop(g);
                repaint();
                g = sh.inner.lock().unwrap();
                continue;
            }
        };
        if let Some(&r) = g.results.get(&sha) {
            g.queue.remove(pos);
            g.states.insert(path, from_cached(r));
            drop(g);
            repaint();
            g = sh.inner.lock().unwrap();
            continue;
        }
        if !g.limiter.try_take((cfg.now_unix)()) {
            g.states.insert(path, VtState::Pending);
            g.paused_until = Some(Instant::now() + cfg.poll);
            continue;
        }
        let key = g.key.clone();
        drop(g);
        let resp = http.get(&sha, &key);
        g = sh.inner.lock().unwrap();

        let outcome = match resp {
            Ok((status, body)) => parse_response(status, &body),
            Err(msg) => VtOutcome::Error(msg),
        };
        match outcome {
            VtOutcome::Done { malicious, total } => {
                g.results.insert(sha, Some((malicious, total)));
                finish(&mut g, &path, VtState::Done { malicious, total });
            }
            VtOutcome::Unknown => {
                g.results.insert(sha, None);
                finish(&mut g, &path, VtState::Unknown);
            }
            VtOutcome::RateLimited => {
                g.states.insert(path, VtState::Pending);
                g.paused_until = Some(Instant::now() + cfg.rate_pause);
            }
            VtOutcome::BadKey => {
                g.bad_key = true;
                let Inner { queue, states, .. } = &mut *g;
                for p in queue.iter() {
                    states.insert(p.clone(), VtState::Error(BAD_KEY_MSG.into()));
                }
            }
            VtOutcome::Error(msg) => {
                g.states.insert(path.clone(), VtState::Error(msg));
                g.retry_at.insert(path, Instant::now() + cfg.retry);
            }
        }
        save_cache(&cache_path, &g);
        drop(g);
        repaint();
        g = sh.inner.lock().unwrap();
    }
}

fn finish(g: &mut Inner, path: &Path, st: VtState) {
    g.queue.retain(|p| p != path);
    g.states.insert(path.to_path_buf(), st);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const BODY: &str = r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":2,"suspicious":1,"undetected":60,"harmless":9,"timeout":0}}}}"#;

    #[test]
    fn parse_200() {
        assert_eq!(parse_response(200, BODY), VtOutcome::Done { malicious: 2, total: 72 });
        assert!(matches!(parse_response(200, "{}"), VtOutcome::Error(_)));
    }

    #[test]
    fn parse_404_unknown() {
        assert_eq!(parse_response(404, ""), VtOutcome::Unknown);
        assert_eq!(parse_response(429, ""), VtOutcome::RateLimited);
        assert_eq!(parse_response(401, ""), VtOutcome::BadKey);
        assert_eq!(parse_response(403, ""), VtOutcome::BadKey);
        assert!(matches!(parse_response(500, ""), VtOutcome::Error(_)));
    }

    #[test]
    fn limiter_4_per_minute() {
        let mut l = RateLimiter::new(4, 500);
        assert!((0..4).all(|i| l.try_take(1000 + i)));
        assert!(!l.try_take(1010));
        assert!(l.try_take(1060)); // first token left the window
    }

    #[test]
    fn limiter_500_per_day_resets_at_utc_midnight() {
        let mut l = RateLimiter::new(1000, 500);
        let day = 20_000 * 86_400;
        for i in 0..500 {
            assert!(l.try_take(day + i), "take {i}");
        }
        assert!(!l.try_take(day + 86_399));
        assert!(l.try_take(day + 86_400));
    }

    type Resp = Result<(u16, String), String>;

    #[derive(Clone, Default)]
    struct Fake {
        calls: Arc<Mutex<Vec<(String, String)>>>,
        script: Arc<Mutex<VecDeque<Resp>>>,
    }

    impl VtHttp for Fake {
        fn get(&self, sha: &str, key: &str) -> Resp {
            self.calls.lock().unwrap().push((sha.into(), key.into()));
            self.script.lock().unwrap().pop_front().unwrap_or_else(|| Ok((200, BODY.into())))
        }
    }

    impl Fake {
        fn calls(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
        fn script(&self, r: Resp) {
            self.script.lock().unwrap().push_back(r);
        }
    }

    fn fast() -> VtConfig {
        VtConfig { rate_pause: Duration::from_millis(150), retry: Duration::from_millis(150), poll: Duration::from_millis(50), ..Default::default() }
    }

    fn svc(dir: &Path, fake: &Fake) -> VtService {
        VtService::with_config(dir.join("vt-cache.json"), Box::new(fake.clone()), "key1".into(), Box::new(|| {}), fast())
    }

    fn file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    fn wait_for(s: &VtService, p: &Path, ok: impl Fn(&VtState) -> bool) -> VtState {
        let t = Instant::now();
        loop {
            let st = s.state(p);
            if ok(&st) {
                return st;
            }
            assert!(t.elapsed() < Duration::from_secs(5), "timed out in state {st:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn done(s: &VtState) -> bool {
        matches!(s, VtState::Done { .. })
    }

    #[test]
    fn same_binary_queried_once() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (file(d.path(), "a", "same"), file(d.path(), "b", "same"));
        let fake = Fake::default();
        let s = svc(d.path(), &fake);
        s.enqueue(&a);
        s.enqueue(&b);
        assert_eq!(wait_for(&s, &a, done), VtState::Done { malicious: 2, total: 72 });
        wait_for(&s, &b, done);
        assert_eq!(fake.calls(), 1);
    }

    #[test]
    fn cache_survives_restart() {
        let d = tempfile::tempdir().unwrap();
        let a = file(d.path(), "a", "x");
        let fake = Fake::default();
        let s = svc(d.path(), &fake);
        s.enqueue(&a);
        wait_for(&s, &a, done);
        drop(s);
        let fake2 = Fake::default();
        let s2 = svc(d.path(), &fake2);
        s2.enqueue(&a);
        wait_for(&s2, &a, done);
        assert_eq!(fake2.calls(), 0);
        let cache = std::fs::read_to_string(d.path().join("vt-cache.json")).unwrap();
        assert!(!cache.contains("key1"));
    }

    #[test]
    fn rate_limited_pauses_and_keeps_item() {
        let d = tempfile::tempdir().unwrap();
        let a = file(d.path(), "a", "x");
        let fake = Fake::default();
        fake.script(Ok((429, String::new())));
        let s = svc(d.path(), &fake);
        s.enqueue(&a);
        let t = Instant::now();
        wait_for(&s, &a, done);
        assert!(t.elapsed() >= Duration::from_millis(150), "did not pause");
        assert_eq!(fake.calls(), 2);
    }

    #[test]
    fn bad_key_stops_queue() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (file(d.path(), "a", "1"), file(d.path(), "b", "2"));
        let fake = Fake::default();
        fake.script(Ok((401, String::new())));
        let s = svc(d.path(), &fake);
        s.enqueue(&a);
        s.enqueue(&b);
        let err = VtState::Error("API anahtarı geçersiz".into());
        wait_for(&s, &a, |st| *st == err);
        wait_for(&s, &b, |st| *st == err);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(fake.calls(), 1);
        s.set_key("key2".into());
        wait_for(&s, &a, done);
        wait_for(&s, &b, done);
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].1, "key2");
    }

    #[test]
    fn offline_retries_later() {
        let d = tempfile::tempdir().unwrap();
        let a = file(d.path(), "a", "x");
        let fake = Fake::default();
        fake.script(Err("offline".into()));
        let s = svc(d.path(), &fake);
        s.enqueue(&a);
        wait_for(&s, &a, |st| *st == VtState::Error("offline".into()));
        assert_eq!(fake.calls(), 1);
        wait_for(&s, &a, done);
        assert_eq!(fake.calls(), 2);
    }

    #[test]
    fn unreadable_file_is_error_not_retried() {
        let d = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let s = svc(d.path(), &fake);
        let p = d.path().join("missing");
        s.enqueue(&p);
        wait_for(&s, &p, |st| *st == VtState::Error("okunamadı".into()));
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(fake.calls(), 0);
        assert_eq!(s.state(&p), VtState::Error("okunamadı".into()));
    }

    #[test]
    fn prioritize_moves_to_front() {
        let d = tempfile::tempdir().unwrap();
        let (a, b, c) = (file(d.path(), "a", "1"), file(d.path(), "b", "2"), file(d.path(), "c", "3"));
        let fake = Fake::default();
        fake.script(Ok((401, String::new()))); // park the queue while we reorder
        let s = svc(d.path(), &fake);
        s.enqueue(&a);
        wait_for(&s, &a, |st| matches!(st, VtState::Error(_)));
        s.enqueue(&b);
        s.enqueue(&c);
        s.prioritize(&c);
        s.set_key("key2".into());
        wait_for(&s, &b, done);
        let calls = fake.calls.lock().unwrap();
        let sha = |t: &str| hash_file(&d.path().join(t)).unwrap().0;
        let order: Vec<_> = calls.iter().skip(1).map(|c| c.0.clone()).collect();
        assert_eq!(order, vec![sha("c"), sha("a"), sha("b")]);
    }
}
