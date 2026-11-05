use crate::darwin::libproc::thread_count;
use crate::model::{ProcInfo, ProcStatus, Snapshot, SystemStats};
use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{
    MemoryRefreshKind, Networks, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System,
    UpdateKind, Users,
};

/// Samples this machine's processes and system stats via `sysinfo`.
pub struct LocalSampler {
    sys: System,
    nets: Networks,
    users: Users,
    kind: ProcessRefreshKind,
    last: Instant,
}

impl Default for LocalSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalSampler {
    pub fn new() -> Self {
        let kind = ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_disk_usage()
            .with_user(UpdateKind::OnlyIfNotSet)
            .with_exe(UpdateKind::OnlyIfNotSet);
        let mut s = Self {
            sys: System::new(),
            nets: Networks::new_with_refreshed_list(),
            users: Users::new_with_refreshed_list(),
            kind,
            last: Instant::now(),
        };
        s.refresh(); // baseline: cpu and deltas are diffs against this
        s
    }

    fn refresh(&mut self) {
        self.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, true, self.kind);
        self.sys.refresh_cpu_usage();
        self.sys
            .refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
        self.nets.refresh(true);
    }

    pub fn sample(&mut self) -> Snapshot {
        let elapsed = self.last.elapsed().as_secs_f64().max(0.001);
        self.last = Instant::now();
        self.refresh();

        let mut procs = HashMap::with_capacity(self.sys.processes().len());
        let (mut dr, mut dw) = (0u64, 0u64);
        let mut refreshed = false;
        for (pid, p) in self.sys.processes() {
            let pid = pid.as_u32() as i32;
            let uid = p.user_id().map(|u| **u).unwrap_or(0);
            let user = user_name(&mut self.users, &mut refreshed, p.user_id());
            let d = p.disk_usage();
            dr += d.read_bytes;
            dw += d.written_bytes;
            procs.insert(
                pid,
                ProcInfo {
                    pid,
                    ppid: p.parent().map_or(0, |pp| pp.as_u32() as i32),
                    name: p.name().to_string_lossy().into_owned(),
                    exe: p.exe().map(|e| e.to_path_buf()),
                    user,
                    uid,
                    cpu: p.cpu_usage(),
                    mem: p.memory(),
                    threads: thread_count(pid).ok(),
                    status: match p.status() {
                        ProcessStatus::Run => ProcStatus::Running,
                        ProcessStatus::Sleep | ProcessStatus::Idle => ProcStatus::Sleeping,
                        ProcessStatus::Stop => ProcStatus::Stopped,
                        ProcessStatus::Zombie => ProcStatus::Zombie,
                        _ => ProcStatus::Other,
                    },
                    start_time: p.start_time(),
                    disk_read: d.read_bytes,
                    disk_write: d.written_bytes,
                },
            );
        }
        let (rx, tx) = self.nets.values().fold((0u64, 0u64), |(r, t), n| {
            (r + n.received(), t + n.transmitted())
        });
        let bps = |b: u64| (b as f64 / elapsed) as u64;

        Snapshot {
            procs,
            system: SystemStats {
                cpu: self.sys.global_cpu_usage().clamp(0.0, 100.0),
                mem_used: self.sys.used_memory(),
                mem_total: self.sys.total_memory(),
                disk_read_bps: bps(dr),
                disk_write_bps: bps(dw),
                net_rx_bps: bps(rx),
                net_tx_bps: bps(tx),
            },
            taken_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
        }
    }
}

/// Cached lookup; refreshes the user list at most once per sample.
fn user_name(users: &mut Users, refreshed: &mut bool, uid: Option<&sysinfo::Uid>) -> String {
    let Some(uid) = uid else { return String::new() };
    if users.get_user_by_id(uid).is_none() && !*refreshed {
        users.refresh();
        *refreshed = true;
    }
    users
        .get_user_by_id(uid)
        .map_or_else(|| uid.to_string(), |u| u.name().to_string())
}
