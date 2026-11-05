//! Process actions. Each guards against PID reuse by comparing the process start time
//! the caller saw with the current one before touching the pid.
use crate::darwin::libproc::{map_errno, start_time};
use crate::model::*;
use std::io;
use std::path::Path;

fn check(pid: Pid, expected_start: u64) -> Result<(), DetailError> {
    // kill(0)/kill(-1) would signal a whole process group / every process; setpriority(0) is self.
    if pid <= 0 {
        return Err(DetailError::NoSuchProcess);
    }
    if start_time(pid)? == expected_start { Ok(()) } else { Err(DetailError::NoSuchProcess) }
}

fn errno_result(rc: i32) -> Result<(), DetailError> {
    if rc == 0 { Ok(()) } else { Err(map_errno(io::Error::last_os_error().raw_os_error().unwrap_or(0))) }
}

// shortcut: check-then-act is racy (pid could be reused in between), narrow window; no pidfd on macOS.
pub fn send_signal(pid: Pid, expected_start: u64, sig: Sig) -> Result<(), DetailError> {
    check(pid, expected_start)?;
    let s = match sig {
        Sig::Term => libc::SIGTERM,
        Sig::Kill => libc::SIGKILL,
        Sig::Stop => libc::SIGSTOP,
        Sig::Cont => libc::SIGCONT,
    };
    errno_result(unsafe { libc::kill(pid, s) })
}

pub fn renice(pid: Pid, expected_start: u64, nice: i32) -> Result<(), DetailError> {
    check(pid, expected_start)?;
    errno_result(unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice.clamp(-20, 20)) })
}

pub fn reveal_in_finder(path: &Path) -> io::Result<()> {
    let st = std::process::Command::new("open").arg("-R").arg(path).status()?;
    if st.success() { Ok(()) } else { Err(io::Error::other(format!("open -R failed: {st}"))) }
}
