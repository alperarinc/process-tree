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

mod actions {
    use procexp::actions::*;
    use procexp::darwin::libproc::start_time;
    use procexp::model::*;
    use procexp::sampler::LocalSampler;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command};

    struct Guard(Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn spawn() -> (Guard, Pid, u64) {
        let c = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = c.id() as Pid;
        let st = start_time(pid).unwrap();
        (Guard(c), pid, st)
    }
    fn ps(pid: Pid, col: &str) -> String {
        let o = Command::new("ps").env("LC_ALL", "C").args(["-o", &format!("{col}="), "-p", &pid.to_string()]).output().unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }
    fn wait_for(f: impl Fn() -> bool) -> bool {
        for _ in 0..50 {
            if f() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn stop_cont_kill_child() {
        let (mut g, pid, st) = spawn();
        send_signal(pid, st, Sig::Stop).unwrap();
        assert!(wait_for(|| ps(pid, "stat").starts_with('T')));
        send_signal(pid, st, Sig::Cont).unwrap();
        assert!(wait_for(|| !ps(pid, "stat").starts_with('T')));
        send_signal(pid, st, Sig::Kill).unwrap();
        assert_eq!(g.0.wait().unwrap().signal(), Some(9));
    }

    #[test]
    fn signal_refuses_mismatched_start_time() {
        let (mut g, pid, st) = spawn();
        assert!(matches!(send_signal(pid, st + 1, Sig::Kill), Err(DetailError::NoSuchProcess)));
        assert!(g.0.try_wait().unwrap().is_none());
    }

    #[test]
    fn nonpositive_pid_is_rejected() {
        // Cont is harmless if the guard were missing: kill(0)/kill(-1) would hit our group / everything.
        for pid in [0, -1] {
            let st = start_time(pid).unwrap_or(0);
            assert!(matches!(send_signal(pid, st, Sig::Cont), Err(DetailError::NoSuchProcess)), "pid {pid}");
            assert!(matches!(renice(pid, st, 10), Err(DetailError::NoSuchProcess)), "pid {pid}");
        }
    }

    #[test]
    fn renice_child_up() {
        let (_g, pid, st) = spawn();
        renice(pid, st, 10).unwrap();
        assert_eq!(ps(pid, "nice"), "10");
        assert!(matches!(renice(pid, st + 1, 5), Err(DetailError::NoSuchProcess)));
    }

    #[test]
    fn renice_down_without_root_is_access_denied() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_g, pid, st) = spawn();
        renice(pid, st, 10).unwrap();
        assert!(matches!(renice(pid, st, 0), Err(DetailError::AccessDenied)));
    }

    #[test]
    fn sampler_start_time_matches_libproc() {
        let (_g, pid, st) = spawn();
        let snap = LocalSampler::new().sample();
        assert_eq!(snap.procs[&pid].start_time, st);
    }
}
