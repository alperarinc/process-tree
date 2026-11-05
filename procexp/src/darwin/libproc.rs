//! Per-process detail readers over libproc / sysctl. Struct layouts and offsets
//! were checked against the SDK's sys/proc_info.h (offsetof on arm64).
use crate::model::*;
use std::collections::BTreeSet;
use std::io;

const PROC_PIDLISTFDS: i32 = 1;
const PROC_PIDLISTTHREADS: i32 = 6;
const PROC_PIDREGIONPATHINFO: i32 = 8;
const PROC_PIDTHREADINFO: i32 = 5;
const PROC_PIDFDVNODEPATHINFO: i32 = 2;
const PROC_PIDFDSOCKETINFO: i32 = 3;

const MAXPATH: usize = 1024;
const VIP_PATH_OFF_FD: usize = 176; // vnode_fdinfowithpath.pvip.vip_path
const VNODE_FD_SIZE: usize = 1200;
const REGION_SIZE: usize = 1272;
const REGION_ADDR_OFF: usize = 80;
const REGION_SIZE_OFF: usize = 88;
const REGION_PATH_OFF: usize = 248;
const VNODEPATH_SIZE: usize = 2352;
const CDIR_PATH_OFF: usize = 152;
const SOCK_SIZE: usize = 792;
const SO_PROTO: usize = 180;
const SO_FAMILY: usize = 184;
const SO_KIND: usize = 256;
const IN_FPORT: usize = 264;
const IN_LPORT: usize = 268;
const IN_VFLAG: usize = 288;
const IN_FADDR: usize = 296;
const IN_LADDR: usize = 312;
const TCP_STATE: usize = 344;
const UN_ADDR: usize = 280; // sockaddr_un: len, family, path[104]
const SUN_PATH: usize = 2;
const TH_NAME_OFF: usize = 48;
const TH_CPU_OFF: usize = 16;
const TH_RUNSTATE_OFF: usize = 24;
const TH_INFO_SIZE: usize = 112;

pub fn map_errno(e: i32) -> DetailError {
    match e {
        libc::EPERM | libc::EACCES => DetailError::AccessDenied,
        libc::ESRCH => DetailError::NoSuchProcess,
        _ => DetailError::Other(io::Error::from_raw_os_error(e).to_string()),
    }
}

fn last_err() -> DetailError {
    match io::Error::last_os_error().raw_os_error() {
        Some(e) if e != 0 => map_errno(e),
        // libproc sometimes returns 0 without errno; treat as a denied read
        _ => DetailError::AccessDenied,
    }
}

fn rd<T: Copy>(b: &[u8], off: usize) -> T {
    assert!(off + std::mem::size_of::<T>() <= b.len());
    unsafe { std::ptr::read_unaligned(b.as_ptr().add(off) as *const T) }
}

fn cstr(b: &[u8], off: usize, max: usize) -> String {
    let s = &b[off..(off + max).min(b.len())];
    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..n]).into_owned()
}

fn pidinfo(pid: Pid, flavor: i32, arg: u64, buf: &mut [u8]) -> Result<usize, DetailError> {
    unsafe { *libc::__error() = 0 };
    let n = unsafe { libc::proc_pidinfo(pid, flavor, arg, buf.as_mut_ptr().cast(), buf.len() as i32) };
    if n <= 0 { Err(last_err()) } else { Ok(n as usize) }
}

pub fn start_time(pid: Pid) -> Result<u64, DetailError> {
    let mut b = [0u8; std::mem::size_of::<libc::proc_bsdinfo>()];
    pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, &mut b)?;
    Ok(unsafe { std::ptr::read_unaligned(b.as_ptr() as *const libc::proc_bsdinfo) }.pbi_start_tvsec)
}

pub fn thread_count(pid: Pid) -> Result<u32, DetailError> {
    let mut b = [0u8; std::mem::size_of::<libc::proc_taskinfo>()];
    pidinfo(pid, libc::PROC_PIDTASKINFO, 0, &mut b)?;
    Ok(unsafe { std::ptr::read_unaligned(b.as_ptr() as *const libc::proc_taskinfo) }.pti_threadnum as u32)
}

fn fmt_addr(b: &[u8], off: usize, port: i32, v6: bool) -> String {
    let port = u16::from_be(port as u16);
    if v6 {
        let a: [u8; 16] = rd(b, off);
        format!("[{}]:{port}", std::net::Ipv6Addr::from(a))
    } else {
        let a: [u8; 4] = rd(b, off + 12); // in4in6_addr: 3 pad words, then the v4 address
        format!("{}:{port}", std::net::Ipv4Addr::from(a))
    }
}

fn tcp_state(s: i32) -> &'static str {
    match s {
        0 => "CLOSED",
        1 => "LISTEN",
        2 => "SYN_SENT",
        3 => "SYN_RECEIVED",
        4 => "ESTABLISHED",
        5 => "CLOSE_WAIT",
        6 => "FIN_WAIT_1",
        7 => "CLOSING",
        8 => "LAST_ACK",
        9 => "FIN_WAIT_2",
        10 => "TIME_WAIT",
        _ => "UNKNOWN",
    }
}

fn socket_entry(fd: i32, b: &[u8]) -> FdEntry {
    let family: i32 = rd(b, SO_FAMILY);
    let protocol: i32 = rd(b, SO_PROTO);
    let kind: i32 = rd(b, SO_KIND);
    let sock = |proto, local, remote, state: &str| FdEntry::Socket { fd, proto, local, remote, state: state.into() };
    match (family, kind) {
        (libc::AF_UNIX, _) => sock(Proto::Unix, cstr(b, UN_ADDR + SUN_PATH, 104), String::new(), ""),
        (libc::AF_INET | libc::AF_INET6, 1 | 2) => {
            let v6 = rd::<u8>(b, IN_VFLAG) & 2 != 0;
            let local = fmt_addr(b, IN_LADDR, rd(b, IN_LPORT), v6);
            let remote = fmt_addr(b, IN_FADDR, rd(b, IN_FPORT), v6);
            match (protocol, kind) {
                (libc::IPPROTO_TCP, 2) => {
                    let p = if v6 { Proto::Tcp6 } else { Proto::Tcp4 };
                    sock(p, local, remote, tcp_state(rd(b, TCP_STATE)))
                }
                (libc::IPPROTO_UDP, _) => sock(if v6 { Proto::Udp6 } else { Proto::Udp4 }, local, remote, ""),
                _ => sock(Proto::Other, local, remote, ""),
            }
        }
        _ => sock(Proto::Other, String::new(), String::new(), ""),
    }
}

pub fn open_fds(pid: Pid) -> Result<Vec<FdEntry>, DetailError> {
    unsafe { *libc::__error() = 0 };
    let need = unsafe { libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Err(last_err());
    }
    let sz = std::mem::size_of::<libc::proc_fdinfo>();
    // slack: fds may be opened between the size query and the read
    let mut list = vec![libc::proc_fdinfo { proc_fd: 0, proc_fdtype: 0 }; need as usize / sz + 16];
    let got = unsafe {
        libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, list.as_mut_ptr().cast(), (list.len() * sz) as i32)
    };
    if got <= 0 {
        return Err(last_err());
    }
    list.truncate(got as usize / sz);
    let mut out = Vec::with_capacity(list.len());
    for f in list {
        let fd = f.proc_fd;
        let fdinfo = |flavor, b: &mut [u8]| unsafe {
            libc::proc_pidfdinfo(pid, fd, flavor, b.as_mut_ptr().cast(), b.len() as i32) > 0
        };
        match f.proc_fdtype as i32 {
            libc::PROX_FDTYPE_VNODE => {
                let mut b = vec![0u8; VNODE_FD_SIZE];
                // fd closed since listing: skip
                if fdinfo(PROC_PIDFDVNODEPATHINFO, &mut b) {
                    out.push(FdEntry::File { fd, path: cstr(&b, VIP_PATH_OFF_FD, MAXPATH) });
                }
            }
            libc::PROX_FDTYPE_SOCKET => {
                let mut b = vec![0u8; SOCK_SIZE];
                if fdinfo(PROC_PIDFDSOCKETINFO, &mut b) {
                    out.push(socket_entry(fd, &b));
                }
            }
            libc::PROX_FDTYPE_PIPE => out.push(FdEntry::Pipe { fd }),
            t => out.push(FdEntry::Other {
                fd,
                kind: match t {
                    libc::PROX_FDTYPE_KQUEUE => "kqueue".into(),
                    libc::PROX_FDTYPE_PSHM => "shm".into(),
                    libc::PROX_FDTYPE_PSEM => "sem".into(),
                    t => format!("type {t}"),
                },
            }),
        }
    }
    Ok(out)
}

pub fn threads(pid: Pid) -> Result<Vec<ThreadEntry>, DetailError> {
    let mut ids = vec![0u64; 4096];
    let n = {
        let b = unsafe { std::slice::from_raw_parts_mut(ids.as_mut_ptr().cast::<u8>(), ids.len() * 8) };
        pidinfo(pid, PROC_PIDLISTTHREADS, 0, b)?
    };
    ids.truncate(n / 8);
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let mut b = [0u8; TH_INFO_SIZE];
        // thread may have exited meanwhile: skip
        if pidinfo(pid, PROC_PIDTHREADINFO, id, &mut b).is_err() {
            continue;
        }
        let state = match rd::<i32>(&b, TH_RUNSTATE_OFF) {
            1 => "running",
            2 => "stopped",
            3 => "waiting",
            4 => "uninterruptible",
            5 => "halted",
            _ => "unknown",
        };
        out.push(ThreadEntry {
            id,
            name: cstr(&b, TH_NAME_OFF, 64),
            cpu: rd::<i32>(&b, TH_CPU_OFF) as f32 / 10.0, // TH_USAGE_SCALE 1000 = 100 %
            state: state.into(),
        });
    }
    Ok(out)
}

pub fn mapped_files(pid: Pid) -> Result<Vec<String>, DetailError> {
    let mut paths = BTreeSet::new();
    let mut addr = 0u64;
    let mut b = vec![0u8; REGION_SIZE];
    loop {
        match pidinfo(pid, PROC_PIDREGIONPATHINFO, addr, &mut b) {
            Ok(_) => {}
            Err(e) if addr == 0 => return Err(e),
            Err(_) => break, // ran past the last region
        }
        let (start, size): (u64, u64) = (rd(&b, REGION_ADDR_OFF), rd(&b, REGION_SIZE_OFF));
        let p = cstr(&b, REGION_PATH_OFF, MAXPATH);
        if !p.is_empty() {
            paths.insert(p);
        }
        match start.checked_add(size) {
            Some(next) if size > 0 && next > addr => addr = next,
            _ => break,
        }
    }
    Ok(paths.into_iter().collect())
}

fn procargs(pid: Pid) -> Result<ProcExtra, DetailError> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut len = 0usize;
    let call = |buf: *mut libc::c_void, len: &mut usize, mib: &mut [i32; 3]| unsafe {
        libc::sysctl(mib.as_mut_ptr(), 3, buf, len, std::ptr::null_mut(), 0)
    };
    if call(std::ptr::null_mut(), &mut len, &mut mib) != 0 {
        return Err(last_err());
    }
    len += 4096; // args may grow between the two calls
    let mut b = vec![0u8; len];
    if call(b.as_mut_ptr().cast(), &mut len, &mut mib) != 0 {
        return Err(last_err());
    }
    b.truncate(len);
    if b.len() < 4 {
        return Err(DetailError::Other("short KERN_PROCARGS2".into()));
    }
    let argc: i32 = rd(&b, 0);
    // layout: argc, exec_path\0, NUL padding, argv[0..argc]\0, env\0..., then empty
    let mut parts = b[4..].split(|&c| c == 0);
    parts.next(); // exec_path
    let mut strs = parts.skip_while(|s| s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned());
    let args: Vec<String> = strs.by_ref().take(argc.max(0) as usize).collect();
    let env = strs
        .take_while(|s| !s.is_empty())
        .filter_map(|s| s.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect();
    Ok(ProcExtra { args, env, cwd: None })
}

pub fn proc_extra(pid: Pid) -> Result<ProcExtra, DetailError> {
    let mut x = procargs(pid)?;
    let mut b = vec![0u8; VNODEPATH_SIZE];
    x.cwd = pidinfo(pid, libc::PROC_PIDVNODEPATHINFO, 0, &mut b)
        .ok()
        .map(|_| cstr(&b, CDIR_PATH_OFF, MAXPATH))
        .filter(|s| !s.is_empty());
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_mapping() {
        assert!(matches!(map_errno(libc::EPERM), DetailError::AccessDenied));
        assert!(matches!(map_errno(libc::EACCES), DetailError::AccessDenied));
        assert!(matches!(map_errno(libc::ESRCH), DetailError::NoSuchProcess));
        assert!(matches!(map_errno(libc::ENOMEM), DetailError::Other(_)));
    }
}
