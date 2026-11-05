//! Temporary root helper: this same binary started as root with `--helper <dir>`, serving one
//! client over `<dir>/sock` with newline-delimited JSON. Everything read from the socket is untrusted.
use crate::backend::{Backend, LocalBackend};
use crate::model::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Sample,
    OpenFds(Pid),
    Threads(Pid),
    MappedFiles(Pid),
    ProcExtra(Pid),
    Signal(Pid, u64, Sig),
    Renice(Pid, u64, i32),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Snapshot(Snapshot),
    Fds(Vec<FdEntry>),
    Threads(Vec<ThreadEntry>),
    Files(Vec<String>),
    Extra(ProcExtra),
    Done,
    Err(DetailError),
}

const MAX_LINE: u64 = 4096;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

fn random_hex(n: usize) -> io::Result<String> {
    let mut b = vec![0u8; n];
    fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// New private dir under `$TMPDIR` with a fresh token in `<dir>/token`.
pub fn prepare_dir() -> io::Result<(PathBuf, String)> {
    let dir = std::env::temp_dir().join(format!("procexp-{}", random_hex(8)?));
    DirBuilder::new().mode(0o700).create(&dir)?; // fails if it already exists
    let token = random_hex(32)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("token"))?
        .write_all(token.as_bytes())?;
    Ok((dir, token))
}

extern "C" {
    // Per-thread cwd (libsystem_pthread, macOS 10.12+, no public header). -1 reverts to the
    // process cwd. Stands in for bindat(), which macOS does not export.
    fn pthread_fchdir_np(fd: libc::c_int) -> libc::c_int;
}

fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Serves exactly one authenticated client, then returns. Runs as root in production.
/// The dir is user-owned, so it is opened once (no symlinks) and everything else is done
/// relative to that fd: the user cannot swap paths under us.
pub fn run_server(dir: &Path) -> io::Result<()> {
    let d = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    let meta = d.metadata()?; // fstat
    if !meta.is_dir() || meta.mode() & 0o077 != 0 || meta.uid() == 0 {
        return Err(io::Error::other(
            "helper dir must be a private user directory",
        ));
    }
    let owner = meta.uid();
    let dfd = d.as_raw_fd();
    let token = read_token(dfd)?;
    cvt(unsafe { libc::unlinkat(dfd, c"token".as_ptr(), 0) })?;
    let listener = bind_sock(dfd)?;
    let r = accept(&listener).and_then(|s| serve(s, owner, token.trim()));
    unsafe { libc::unlinkat(dfd, c"sock".as_ptr(), 0) };
    r
}

/// Opens `token` without following symlinks or blocking on a FIFO; regular file, at most 65 bytes.
fn read_token(dfd: libc::c_int) -> io::Result<String> {
    let fd = cvt(unsafe {
        libc::openat(
            dfd,
            c"token".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    })?;
    let f = unsafe { fs::File::from_raw_fd(fd) };
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("token is not a regular file"));
    }
    let mut token = String::new();
    f.take(65).read_to_string(&mut token)?;
    Ok(token)
}

/// Binds `sock` inside the already-checked dir fd (relative to this thread's cwd).
fn bind_sock(dfd: libc::c_int) -> io::Result<UnixListener> {
    cvt(unsafe { pthread_fchdir_np(dfd) })?;
    // Socket must be connectable by the (non-root) owner; the 0700 dir already restricts access.
    // umask instead of chown/chmod-by-path: nothing to race with a swapped-in symlink.
    let old = unsafe { libc::umask(0) };
    let l = UnixListener::bind("sock");
    unsafe { libc::umask(old) };
    cvt(unsafe { pthread_fchdir_np(-1) })?;
    l
}

fn accept(l: &UnixListener) -> io::Result<UnixStream> {
    l.set_nonblocking(true)?;
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false)?;
                return Ok(s);
            }
            Err(e) if e.kind() != io::ErrorKind::WouldBlock => return Err(e),
            Err(_) if Instant::now() >= deadline => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no client"))
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn serve(s: UnixStream, owner: u32, token: &str) -> io::Result<()> {
    let (mut uid, mut gid) = (0, 0);
    if unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let denied = |m| Err(io::Error::new(io::ErrorKind::PermissionDenied, m));
    if uid != owner {
        return denied("peer uid is not the dir owner");
    }
    s.set_read_timeout(Some(ACCEPT_TIMEOUT))?;
    let mut r = BufReader::new(s.try_clone()?);
    let mut w = s;
    // shortcut: non-constant-time compare; the server exits after one try, so no timing oracle.
    if read_line(&mut r)?.as_deref() != Some(token) {
        return denied("bad token");
    }
    w.set_read_timeout(None)?; // the GUI may idle between requests
    let mut backend = LocalBackend::new();
    while let Some(line) = read_line(&mut r)? {
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle(&mut backend, req),
            Err(e) => Response::Err(DetailError::Other(format!("bad request: {e}"))),
        };
        let mut out = serde_json::to_string(&resp).unwrap_or_else(|e| {
            serde_json::to_string(&Response::Err(DetailError::Other(e.to_string())))
                .expect("error response serializes")
        });
        out.push('\n');
        w.write_all(out.as_bytes())?;
    }
    Ok(())
}

/// `None` on EOF; error on an over-long, unterminated or non-UTF-8 line.
fn read_line(r: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut line = String::new();
    if r.by_ref().take(MAX_LINE).read_line(&mut line)? == 0 {
        return Ok(None);
    }
    if line.pop() != Some('\n') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
    }
    Ok(Some(line))
}

fn handle(b: &mut impl Backend, req: Request) -> Response {
    let r = match req {
        Request::Sample => b.sample().map(|mut s| {
            lossy_exes(&mut s);
            Response::Snapshot(s)
        }),
        Request::OpenFds(p) => b.open_fds(p).map(Response::Fds),
        Request::Threads(p) => b.threads(p).map(Response::Threads),
        Request::MappedFiles(p) => b.mapped_files(p).map(Response::Files),
        Request::ProcExtra(p) => b.proc_extra(p).map(Response::Extra),
        Request::Signal(p, st, sig) => b.signal(p, st, sig).map(|()| Response::Done),
        Request::Renice(p, st, n) => b.renice(p, st, n).map(|()| Response::Done),
    };
    r.unwrap_or_else(Response::Err)
}

/// serde refuses non-UTF-8 paths; one odd exe must not fail the whole Sample.
fn lossy_exes(s: &mut Snapshot) {
    for p in s.procs.values_mut() {
        if p.exe.as_ref().is_some_and(|e| e.to_str().is_none()) {
            p.exe = p
                .exe
                .take()
                .map(|e| e.to_string_lossy().into_owned().into());
        }
    }
}

/// Runs `exe --helper dir` as root via the macOS admin password prompt. Err if the user cancels.
pub fn launch(exe: &Path, dir: &Path) -> io::Result<()> {
    let st = Command::new("osascript")
        .args([
            "-e",
            "on run argv",
            "-e",
            r#"do shell script (quoted form of item 1 of argv) & " --helper " & (quoted form of item 2 of argv) & " >/dev/null 2>&1 &" with administrator privileges"#,
            "-e",
            "end run",
        ])
        .arg(exe)
        .arg(dir)
        .status()?;
    if st.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("osascript: {st}")))
    }
}

/// `Backend` over the helper socket. After any I/O or protocol error it stays `Disconnected`.
pub struct HelperClient {
    conn: Option<(BufReader<UnixStream>, UnixStream)>,
    dir: PathBuf,
}

impl HelperClient {
    /// Connects to the root helper; refuses a server not running as root.
    pub fn connect(dir: &Path, token: &str, timeout: Duration) -> io::Result<Self> {
        Self::connect_expecting(dir, token, timeout, 0)
    }

    /// Like `connect`, but the server must run as `uid` (tests run it as the current user).
    pub fn connect_expecting(
        dir: &Path,
        token: &str,
        timeout: Duration,
        uid: u32,
    ) -> io::Result<Self> {
        let sock = dir.join("sock");
        let deadline = Instant::now() + timeout;
        let mut s = loop {
            match UnixStream::connect(&sock) {
                Ok(s) => break s,
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        };
        // Check the peer before the token leaves this process.
        let (mut peer, mut gid) = (0, 0);
        cvt(unsafe { libc::getpeereid(s.as_raw_fd(), &mut peer, &mut gid) })?;
        if peer != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("helper runs as uid {peer}, expected {uid}"),
            ));
        }
        s.write_all(format!("{token}\n").as_bytes())?;
        s.set_read_timeout(Some(REPLY_TIMEOUT))?;
        Ok(Self {
            conn: Some((BufReader::new(s.try_clone()?), s)),
            dir: dir.to_path_buf(),
        })
    }

    /// Best-effort: drop the connection and remove our temp dir (the helper never comes back).
    fn close(&mut self) {
        if self.conn.take().is_some() {
            let _ = fs::remove_file(self.dir.join("sock"));
            let _ = fs::remove_dir(&self.dir);
        }
    }

    fn call(&mut self, req: &Request) -> Result<Response, DetailError> {
        let Some((r, w)) = self.conn.as_mut() else {
            return Err(DetailError::Disconnected);
        };
        let res = (|| -> io::Result<Response> {
            let mut line = serde_json::to_string(req)?;
            line.push('\n');
            w.write_all(line.as_bytes())?;
            let mut buf = String::new();
            if r.read_line(&mut buf)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(serde_json::from_str(&buf)?)
        })();
        match res {
            Ok(Response::Err(e)) => Err(e),
            Ok(resp) => Ok(resp),
            Err(_) => self.dead(),
        }
    }

    fn dead<T>(&mut self) -> Result<T, DetailError> {
        self.close();
        Err(DetailError::Disconnected)
    }
}

impl Drop for HelperClient {
    fn drop(&mut self) {
        self.close();
    }
}

impl Backend for HelperClient {
    fn sample(&mut self) -> Result<Snapshot, DetailError> {
        match self.call(&Request::Sample)? {
            Response::Snapshot(s) => Ok(s),
            _ => self.dead(),
        }
    }
    fn open_fds(&mut self, pid: Pid) -> Result<Vec<FdEntry>, DetailError> {
        match self.call(&Request::OpenFds(pid))? {
            Response::Fds(v) => Ok(v),
            _ => self.dead(),
        }
    }
    fn threads(&mut self, pid: Pid) -> Result<Vec<ThreadEntry>, DetailError> {
        match self.call(&Request::Threads(pid))? {
            Response::Threads(v) => Ok(v),
            _ => self.dead(),
        }
    }
    fn mapped_files(&mut self, pid: Pid) -> Result<Vec<String>, DetailError> {
        match self.call(&Request::MappedFiles(pid))? {
            Response::Files(v) => Ok(v),
            _ => self.dead(),
        }
    }
    fn proc_extra(&mut self, pid: Pid) -> Result<ProcExtra, DetailError> {
        match self.call(&Request::ProcExtra(pid))? {
            Response::Extra(v) => Ok(v),
            _ => self.dead(),
        }
    }
    fn signal(&mut self, pid: Pid, start: u64, sig: Sig) -> Result<(), DetailError> {
        match self.call(&Request::Signal(pid, start, sig))? {
            Response::Done => Ok(()),
            _ => self.dead(),
        }
    }
    fn renice(&mut self, pid: Pid, start: u64, nice: i32) -> Result<(), DetailError> {
        match self.call(&Request::Renice(pid, start, nice))? {
            Response::Done => Ok(()),
            _ => self.dead(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;

    const T: Duration = Duration::from_secs(5);
    const SEC: Duration = Duration::from_secs(1);

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn spawn_server(dir: &Path) -> mpsc::Receiver<io::Result<()>> {
        let (tx, rx) = mpsc::channel();
        let d = dir.to_path_buf();
        thread::spawn(move || {
            let _ = tx.send(run_server(&d));
        });
        rx
    }

    fn start() -> (Dir, String, mpsc::Receiver<io::Result<()>>) {
        let (dir, token) = prepare_dir().unwrap();
        let rx = spawn_server(&dir);
        (Dir(dir), token, rx)
    }

    fn me() -> Pid {
        std::process::id() as Pid
    }

    /// Test servers run as us, not root.
    fn connect(dir: &Path, token: &str, t: Duration) -> io::Result<HelperClient> {
        HelperClient::connect_expecting(dir, token, t, unsafe { libc::getuid() })
    }

    #[test]
    fn client_refuses_non_root_server() {
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        let (dir, token, rx) = start();
        let e = HelperClient::connect(&dir.0, &token, T)
            .err()
            .expect("must refuse");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        // Token never sent: the server sees EOF instead and rejects.
        assert!(rx.recv_timeout(SEC).unwrap().is_err());
    }

    #[test]
    fn client_drop_removes_dir() {
        let (dir, token, rx) = start();
        let c = connect(&dir.0, &token, T).unwrap();
        drop(c);
        assert!(!dir.0.exists());
        // Server may not have accepted yet (then getpeereid fails): it must still exit.
        let _ = rx.recv_timeout(SEC).unwrap();
    }

    #[test]
    fn swapped_paths_are_refused() {
        use std::os::unix::fs::symlink;
        // token as symlink to a readable file
        let (dir, _) = prepare_dir().unwrap();
        let dir = Dir(dir);
        fs::remove_file(dir.0.join("token")).unwrap();
        symlink("/etc/hosts", dir.0.join("token")).unwrap();
        assert!(run_server(&dir.0).is_err());
        // token as FIFO: must not block
        fs::remove_file(dir.0.join("token")).unwrap();
        let c = std::ffi::CString::new(dir.0.join("token").into_os_string().into_encoded_bytes())
            .unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let rx = spawn_server(&dir.0);
        assert!(rx.recv_timeout(SEC).unwrap().is_err());
        // dir itself as symlink to a valid helper dir
        let (real, _) = prepare_dir().unwrap();
        let real = Dir(real);
        let link = Dir(real.0.with_extension("link"));
        symlink(&real.0, &link.0).unwrap();
        assert!(run_server(&link.0).is_err());
        assert!(real.0.join("token").exists());
    }

    #[test]
    fn client_samples_through_server() {
        let (dir, token, _rx) = start();
        let mut c = connect(&dir.0, &token, T).unwrap();
        let snap = c.sample().unwrap();
        assert!(snap.procs.contains_key(&me()));
        assert!(!c.threads(me()).unwrap().is_empty());
        assert!(matches!(
            c.signal(0, 0, Sig::Cont),
            Err(DetailError::NoSuchProcess)
        ));
    }

    #[test]
    fn wrong_token_is_rejected() {
        let (dir, _token, rx) = start();
        let mut c = connect(&dir.0, "nope", T).unwrap();
        assert!(matches!(c.sample(), Err(DetailError::Disconnected)));
        assert!(rx.recv_timeout(SEC).unwrap().is_err());
    }

    #[test]
    fn client_reports_disconnected_after_server_exit() {
        let (dir, token) = prepare_dir().unwrap();
        let dir = Dir(dir);
        let l = UnixListener::bind(dir.0.join("sock")).unwrap();
        // Fake server: takes the token line, then dies (drops the stream).
        let h = thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&s).read_line(&mut line).unwrap();
            line
        });
        let mut c = connect(&dir.0, &token, T).unwrap();
        assert_eq!(h.join().unwrap().trim_end(), token);
        let t = Instant::now();
        assert!(matches!(c.sample(), Err(DetailError::Disconnected)));
        assert!(matches!(c.threads(me()), Err(DetailError::Disconnected)));
        assert!(t.elapsed() < SEC, "{:?}", t.elapsed());
    }

    #[test]
    fn server_exits_when_client_drops() {
        let (dir, token, rx) = start();
        let mut c = connect(&dir.0, &token, T).unwrap();
        c.proc_extra(me()).unwrap();
        drop(c);
        rx.recv_timeout(SEC).unwrap().unwrap();
        assert!(!dir.0.join("sock").exists());
    }

    #[test]
    fn token_file_removed_and_dir_private() {
        let (dir, token) = prepare_dir().unwrap();
        let dir = Dir(dir);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(mode(&dir.0.join("token")), 0o600);
        let _rx = spawn_server(&dir.0);
        let _c = connect(&dir.0, &token, T).unwrap();
        assert!(!dir.0.join("token").exists());
        assert_eq!(mode(&dir.0), 0o700);
        assert_ne!(prepare_dir().map(|(d, t)| (Dir(d), t)).unwrap().1, token);
    }

    #[test]
    fn untrusted_input_never_panics() {
        let (dir, token, rx) = start();
        let t = Instant::now();
        let mut s = loop {
            match UnixStream::connect(dir.0.join("sock")) {
                Ok(s) => break s,
                Err(e) if t.elapsed() > T => panic!("{e}"),
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        };
        let mut r = BufReader::new(s.try_clone().unwrap());
        let mut ask = |s: &mut UnixStream, line: &[u8]| {
            s.write_all(line).unwrap();
            let mut out = String::new();
            r.read_line(&mut out).unwrap();
            out
        };
        s.write_all(format!("{token}\n").as_bytes()).unwrap();
        let out = ask(&mut s, b"{not json\n");
        assert!(
            matches!(
                serde_json::from_str(&out).unwrap(),
                Response::Err(DetailError::Other(_))
            ),
            "{out}"
        );
        let out = ask(&mut s, b"{\"Signal\":[-1,0,\"Kill\"]}\n");
        assert!(
            matches!(
                serde_json::from_str(&out).unwrap(),
                Response::Err(DetailError::NoSuchProcess)
            ),
            "{out}"
        );
        // Oversized line: server drops the connection instead of buffering forever.
        let _ = s.write_all(&vec![b'x'; 1 << 20]);
        rx.recv_timeout(T).unwrap().unwrap_err();
    }

    #[test]
    fn non_utf8_exe_does_not_break_sample() {
        use std::os::unix::ffi::OsStrExt;
        let exe = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/odd\xff"));
        let p = ProcInfo {
            pid: 1,
            ppid: 0,
            name: "odd".into(),
            exe: Some(exe),
            user: String::new(),
            uid: 0,
            cpu: 0.0,
            mem: 0,
            threads: None,
            status: ProcStatus::Other,
            start_time: 0,
            disk_read: 0,
            disk_write: 0,
        };
        let mut snap = Snapshot {
            procs: [(1, p)].into(),
            system: SystemStats {
                cpu: 0.0,
                mem_used: 0,
                mem_total: 0,
                disk_read_bps: 0,
                disk_write_bps: 0,
                net_rx_bps: 0,
                net_tx_bps: 0,
            },
            taken_at_ms: 0,
        };
        assert!(serde_json::to_string(&snap).is_err());
        lossy_exes(&mut snap);
        let out = serde_json::to_string(&Response::Snapshot(snap)).unwrap();
        assert!(out.contains("/tmp/odd\u{fffd}"), "{out}");
    }
}
