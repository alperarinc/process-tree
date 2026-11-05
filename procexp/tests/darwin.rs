use procexp::darwin::libproc::*;
use procexp::model::*;
use std::net::TcpListener;
use std::process::Command;

fn me() -> Pid {
    std::process::id() as Pid
}

#[test]
fn own_thread_count_grows() {
    // Other tests' threads come and go, so assert a floor instead of a delta:
    // while 8 sleepers are alive the count includes them plus this thread.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
    let hs: Vec<_> = (0..8)
        .map(|_| {
            let rx = rx.clone();
            std::thread::spawn(move || {
                let _ = rx.lock().unwrap().recv();
            })
        })
        .collect();
    let n = thread_count(me()).unwrap();
    drop(tx);
    for h in hs {
        h.join().unwrap();
    }
    assert!(n >= 9, "n={n}");
}

#[test]
fn open_file_is_listed() {
    let f = tempfile::NamedTempFile::new().unwrap();
    // proc_pidfdinfo reports the resolved path (/private/var/... for /var/...)
    let want = std::fs::canonicalize(f.path()).unwrap();
    let want = want.to_str().unwrap();
    assert!(open_fds(me())
        .unwrap()
        .iter()
        .any(|e| matches!(e, FdEntry::File { path, .. } if path == want)));
}

#[test]
fn tcp_listener_is_listed() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    assert!(open_fds(me()).unwrap().iter().any(|e| matches!(e,
        FdEntry::Socket{local, state, ..} if local.ends_with(&format!(":{port}")) && state == "LISTEN")));
}

#[test]
fn established_and_unix_and_pipe_are_listed() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (_s, _) = l.accept().unwrap();
    let cport = c.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s");
    let _u = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let all = open_fds(me()).unwrap();
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    assert!(all.iter().any(|e| matches!(e,
        FdEntry::Socket{proto: Proto::Tcp4, local, remote, state, ..}
            if local.ends_with(&format!(":{cport}")) && remote.starts_with("127.0.0.1:") && state == "ESTABLISHED")));
    assert!(all.iter().any(|e| matches!(e,
        FdEntry::Socket{proto: Proto::Unix, local, ..} if local == sock.to_str().unwrap())));
    assert!(all
        .iter()
        .any(|e| matches!(e, FdEntry::Pipe { fd } if *fd == fds[0])));
}

#[test]
fn threads_have_ids() {
    let t = threads(me()).unwrap();
    assert!(!t.is_empty());
    assert!(t.iter().all(|t| t.id != 0));
}

#[test]
fn libsystem_is_mapped() {
    assert!(!mapped_files(me()).unwrap().is_empty());
}

#[test]
fn own_args_env_cwd() {
    let x = proc_extra(me()).unwrap();
    assert!(!x.args.is_empty());
    assert!(x.env.iter().any(|(k, _)| k == "PATH"));
    assert_eq!(
        x.cwd.unwrap(),
        std::env::current_dir().unwrap().to_str().unwrap()
    );
}

#[test]
fn launchd_needs_root() {
    if unsafe { libc::geteuid() } != 0 {
        assert!(matches!(open_fds(1), Err(DetailError::AccessDenied)));
    }
}

#[test]
fn details_of_exited_process_is_no_such_process() {
    let mut c = Command::new("true").spawn().unwrap();
    let pid = c.id() as i32;
    c.wait().unwrap();
    assert!(matches!(open_fds(pid), Err(DetailError::NoSuchProcess)));
}

#[test]
fn start_time_is_recent_for_child() {
    let mut c = Command::new("sleep").arg("5").spawn().unwrap();
    let st = start_time(c.id() as i32);
    c.kill().unwrap();
    c.wait().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let st = st.unwrap();
    assert!(now.abs_diff(st) <= 5, "st={st} now={now}");
}

#[test]
fn proc_extra_of_launchd_needs_root() {
    if unsafe { libc::geteuid() } != 0 {
        assert!(matches!(proc_extra(1), Err(DetailError::AccessDenied)));
    }
}

#[test]
fn proc_extra_of_exited_process_is_no_such_process() {
    let mut c = Command::new("true").spawn().unwrap();
    let pid = c.id() as i32;
    c.wait().unwrap();
    assert!(matches!(proc_extra(pid), Err(DetailError::NoSuchProcess)));
}

mod sampler {
    use super::*;
    use procexp::sampler::LocalSampler;
    use std::time::{Duration, Instant};

    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn snapshot_contains_self_with_parent() {
        let snap = LocalSampler::new().sample();
        let p = snap.procs.get(&me()).expect("self in snapshot");
        assert_eq!(p.ppid, unsafe { libc::getppid() });
        assert!(p.threads.unwrap() >= 1);
        assert!(p.mem > 0);
    }

    #[test]
    fn child_appears_under_parent() {
        let child = Kill(Command::new("sleep").arg("5").spawn().unwrap());
        let snap = LocalSampler::new().sample();
        let c = snap
            .procs
            .get(&(child.0.id() as Pid))
            .expect("child in snapshot");
        assert_eq!(c.ppid, me());
    }

    #[test]
    fn second_sample_has_cpu_for_busy_thread() {
        let mut s = LocalSampler::new();
        s.sample();
        let t0 = Instant::now();
        let h = std::thread::spawn(move || {
            while t0.elapsed() < Duration::from_millis(1500) {
                std::hint::black_box(0u64);
            }
        });
        std::thread::sleep(Duration::from_millis(1500));
        let snap = s.sample();
        h.join().unwrap();
        let cpu = snap.procs[&me()].cpu;
        assert!(cpu > 20.0, "cpu={cpu}");
    }

    #[test]
    fn system_totals_sane() {
        let mut s = LocalSampler::new();
        s.sample();
        std::thread::sleep(Duration::from_millis(300));
        let sys = s.sample().system;
        assert!(sys.mem_total > sys.mem_used && sys.mem_used > 0);
        assert!((0.0..=100.0).contains(&sys.cpu), "cpu={}", sys.cpu);
    }

    #[test]
    #[ignore]
    fn bench_sample_wall_time() {
        let mut s = LocalSampler::new();
        s.sample();
        let t = Instant::now();
        for _ in 0..10 {
            s.sample();
        }
        let avg = t.elapsed() / 10;
        println!("avg sample = {avg:?}");
        assert!(avg < Duration::from_millis(30), "avg={avg:?}");
    }
}
