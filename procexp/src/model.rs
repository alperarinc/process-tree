use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

pub type Pid = i32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProcStatus {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: Pid,
    pub ppid: Pid,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub user: String,
    pub uid: u32,
    /// Per-core percent: 100 = one full core.
    pub cpu: f32,
    /// Resident set size in bytes.
    pub mem: u64,
    pub threads: Option<u32>,
    pub status: ProcStatus,
    /// Unix seconds.
    pub start_time: u64,
    /// Bytes since the previous sample.
    pub disk_read: u64,
    pub disk_write: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemStats {
    /// Whole machine, 0-100.
    pub cpu: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub procs: HashMap<Pid, ProcInfo>,
    pub system: SystemStats,
    pub taken_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Proto {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
    Unix,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FdEntry {
    File {
        fd: i32,
        path: String,
    },
    Socket {
        fd: i32,
        proto: Proto,
        local: String,
        remote: String,
        state: String,
    },
    Pipe {
        fd: i32,
    },
    Other {
        fd: i32,
        kind: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadEntry {
    pub id: u64,
    pub name: String,
    pub cpu: f32,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcExtra {
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DetailError {
    AccessDenied,
    NoSuchProcess,
    Disconnected,
    Other(String),
}

impl fmt::Display for DetailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetailError::AccessDenied => f.write_str("Access denied — turn on Admin mode"),
            DetailError::NoSuchProcess => f.write_str("Process exited"),
            DetailError::Disconnected => f.write_str("Admin connection lost"),
            DetailError::Other(s) => f.write_str(s),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Sig {
    Term,
    Kill,
    Stop,
    Cont,
}
