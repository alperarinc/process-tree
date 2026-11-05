//! Background cache of per-executable metadata (signing, description, icon).
use crate::darwin::meta;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};

pub struct Meta {
    pub description: Option<String>,
    pub company: Option<String>,
    pub signing: Option<meta::Signing>,
    pub icon: Option<Arc<Vec<u8>>>,
}

const ICON_SIZE: u32 = 32; // drawn at 16 pt on Retina

#[derive(Default)]
struct State {
    done: HashMap<PathBuf, Arc<Meta>>,
    queued: HashSet<PathBuf>,
}

pub struct MetaCache {
    state: Arc<Mutex<State>>,
    tx: Sender<PathBuf>,
}

fn compute(exe: &Path) -> Meta {
    let signing = meta::signing_info(exe);
    let bundle = meta::bundle_root(exe);
    let description = bundle.as_deref().and_then(meta::bundle_description);
    let company = signing.as_ref().and_then(|s| s.company.clone());
    // Nonexistent paths: skip AppKit, which would hand back a generic icon.
    let icon = exe.exists().then(|| meta::icon_rgba(exe, ICON_SIZE)).flatten().map(Arc::new);
    Meta { description, company, signing, icon }
}

impl MetaCache {
    pub fn new(repaint: Box<dyn Fn() + Send>) -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let (tx, rx) = channel::<PathBuf>();
        let st = state.clone();
        std::thread::Builder::new()
            .name("metacache".into())
            .spawn(move || {
                crate::darwin::set_background_qos();
                for path in rx {
                    let m = Arc::new(compute(&path));
                    let mut s = st.lock().unwrap();
                    s.queued.remove(&path);
                    s.done.insert(path, m);
                    drop(s);
                    repaint();
                }
            })
            .expect("spawn metacache");
        Self { state, tx }
    }

    /// Non-blocking: returns the cached entry, or enqueues the path and returns None.
    pub fn get(&self, exe: &Path) -> Option<Arc<Meta>> {
        let mut s = self.state.lock().unwrap();
        if let Some(m) = s.done.get(exe) {
            return Some(m.clone());
        }
        if s.queued.insert(exe.to_path_buf()) {
            let _ = self.tx.send(exe.to_path_buf());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn wait(c: &MetaCache, p: &Path) -> Arc<Meta> {
        let t = Instant::now();
        loop {
            if let Some(m) = c.get(p) {
                return m;
            }
            assert!(t.elapsed() < Duration::from_secs(5), "timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn metacache_eventually_fills() {
        let c = MetaCache::new(Box::new(|| {}));
        let p = Path::new("/System/Applications/Calculator.app/Contents/MacOS/Calculator");
        assert!(c.get(p).is_none());
        let m = wait(&c, p);
        assert!(m.description.is_some() && m.icon.is_some());
    }

    #[test]
    fn nonexistent_path_caches_empty_meta() {
        let c = MetaCache::new(Box::new(|| {}));
        let m = wait(&c, Path::new("/nonexistent/zzz"));
        assert!(m.description.is_none() && m.company.is_none() && m.signing.is_none() && m.icon.is_none());
        assert!(c.get(Path::new("/nonexistent/zzz")).is_some());
    }
}
