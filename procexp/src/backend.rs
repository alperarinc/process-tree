//! Where process data and actions come from: this process (`LocalBackend`) or the root helper.
use crate::actions;
use crate::darwin::libproc;
use crate::model::*;
use crate::sampler::LocalSampler;

pub trait Backend: Send {
    fn sample(&mut self) -> Result<Snapshot, DetailError>;
    fn open_fds(&mut self, pid: Pid) -> Result<Vec<FdEntry>, DetailError>;
    fn threads(&mut self, pid: Pid) -> Result<Vec<ThreadEntry>, DetailError>;
    fn mapped_files(&mut self, pid: Pid) -> Result<Vec<String>, DetailError>;
    fn proc_extra(&mut self, pid: Pid) -> Result<ProcExtra, DetailError>;
    fn signal(&mut self, pid: Pid, start: u64, sig: Sig) -> Result<(), DetailError>;
    fn renice(&mut self, pid: Pid, start: u64, nice: i32) -> Result<(), DetailError>;
    fn privileged(&self) -> bool;
}

#[derive(Default)]
pub struct LocalBackend {
    sampler: LocalSampler,
}

impl LocalBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for LocalBackend {
    fn sample(&mut self) -> Result<Snapshot, DetailError> {
        Ok(self.sampler.sample())
    }
    fn open_fds(&mut self, pid: Pid) -> Result<Vec<FdEntry>, DetailError> {
        libproc::open_fds(pid)
    }
    fn threads(&mut self, pid: Pid) -> Result<Vec<ThreadEntry>, DetailError> {
        libproc::threads(pid)
    }
    fn mapped_files(&mut self, pid: Pid) -> Result<Vec<String>, DetailError> {
        libproc::mapped_files(pid)
    }
    fn proc_extra(&mut self, pid: Pid) -> Result<ProcExtra, DetailError> {
        libproc::proc_extra(pid)
    }
    fn signal(&mut self, pid: Pid, start: u64, sig: Sig) -> Result<(), DetailError> {
        actions::send_signal(pid, start, sig)
    }
    fn renice(&mut self, pid: Pid, start: u64, nice: i32) -> Result<(), DetailError> {
        actions::renice(pid, start, nice)
    }
    fn privileged(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }
}
