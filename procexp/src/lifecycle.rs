use crate::model::{Pid, ProcInfo, Snapshot};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Life {
    New,
    Normal,
    Exited,
}

/// Tracks process birth/exit across snapshots. Identity is `(pid, start_time)`.
pub struct Tracker {
    highlight: Duration,
    first: bool,
    /// Live processes; `Some(t)` = first seen at `t` (still highlighted until it expires).
    live: HashMap<Pid, (ProcInfo, Option<Instant>)>,
    ghosts: Vec<(ProcInfo, Instant)>,
}

impl Tracker {
    pub fn new(highlight: Duration) -> Self {
        Self { highlight, first: true, live: HashMap::new(), ghosts: Vec::new() }
    }

    pub fn update(&mut self, snap: &Snapshot, now: Instant) {
        let mut old = std::mem::take(&mut self.live);
        for (pid, p) in &snap.procs {
            let entry = match old.remove(pid) {
                Some((prev, born)) if prev.start_time == p.start_time => (p.clone(), born),
                prev => {
                    if let Some((prev, _)) = prev {
                        self.ghosts.push((prev, now));
                    }
                    (p.clone(), (!self.first).then_some(now))
                }
            };
            self.live.insert(*pid, entry);
        }
        self.ghosts.extend(old.into_values().map(|(p, _)| (p, now)));
        self.first = false;

        let h = self.highlight;
        self.ghosts.retain(|(_, t)| now.duration_since(*t) < h);
        for (_, born) in self.live.values_mut() {
            if born.is_some_and(|t| now.duration_since(t) >= h) {
                *born = None;
            }
        }
    }

    pub fn life(&self, pid: Pid) -> Life {
        match self.live.get(&pid) {
            Some((_, Some(_))) => Life::New,
            Some((_, None)) => Life::Normal,
            None if self.ghosts.iter().any(|(p, _)| p.pid == pid) => Life::Exited,
            None => Life::Normal,
        }
    }

    pub fn ghosts(&self) -> Vec<ProcInfo> {
        self.ghosts.iter().map(|(p, _)| p.clone()).collect()
    }
}

/// Fixed-capacity history buffer; oldest entries are dropped first.
pub struct Ring<T> {
    cap: usize,
    buf: VecDeque<T>,
}

impl<T> Ring<T> {
    pub fn new(cap: usize) -> Self {
        Self { cap, buf: VecDeque::with_capacity(cap) }
    }

    pub fn push(&mut self, v: T) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(v);
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.buf.iter()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProcStatus, SystemStats};

    fn p(pid: Pid, start: u64) -> ProcInfo {
        ProcInfo {
            pid,
            ppid: 0,
            name: "x".into(),
            exe: None,
            user: "u".into(),
            uid: 0,
            cpu: 0.0,
            mem: 0,
            threads: None,
            status: ProcStatus::Running,
            start_time: start,
            disk_read: 0,
            disk_write: 0,
        }
    }

    fn snap(ps: &[ProcInfo]) -> Snapshot {
        Snapshot {
            procs: ps.iter().map(|p| (p.pid, p.clone())).collect(),
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
        }
    }

    const H: Duration = Duration::from_secs(3);

    #[test]
    fn first_update_is_normal() {
        let mut t = Tracker::new(H);
        t.update(&snap(&[p(1, 1), p(2, 1)]), Instant::now());
        assert_eq!(t.life(1), Life::Normal);
        assert_eq!(t.life(2), Life::Normal);
    }

    #[test]
    fn new_process_is_new_then_normal_after_highlight() {
        let (mut t, t0) = (Tracker::new(H), Instant::now());
        t.update(&snap(&[p(1, 1)]), t0);
        t.update(&snap(&[p(1, 1), p(2, 5)]), t0 + Duration::from_secs(1));
        assert_eq!(t.life(2), Life::New);
        t.update(&snap(&[p(1, 1), p(2, 5)]), t0 + Duration::from_secs(2));
        assert_eq!(t.life(2), Life::New);
        t.update(&snap(&[p(1, 1), p(2, 5)]), t0 + Duration::from_secs(5));
        assert_eq!(t.life(2), Life::Normal);
    }

    #[test]
    fn exited_process_is_ghost_then_dropped() {
        let (mut t, t0) = (Tracker::new(H), Instant::now());
        t.update(&snap(&[p(1, 1), p(2, 1)]), t0);
        t.update(&snap(&[p(1, 1)]), t0 + Duration::from_secs(1));
        assert_eq!(t.life(2), Life::Exited);
        assert_eq!(t.ghosts().len(), 1);
        t.update(&snap(&[p(1, 1)]), t0 + Duration::from_secs(5));
        assert!(t.ghosts().is_empty());
        assert_eq!(t.life(2), Life::Normal);
    }

    #[test]
    fn pid_reuse_is_exit_plus_new() {
        let (mut t, t0) = (Tracker::new(H), Instant::now());
        t.update(&snap(&[p(1, 1)]), t0);
        t.update(&snap(&[p(1, 9)]), t0 + Duration::from_secs(1));
        assert_eq!(t.life(1), Life::New);
        let g = t.ghosts();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].start_time, 1);
    }

    #[test]
    fn ring_drops_oldest() {
        let mut r = Ring::new(3);
        (1..=5).for_each(|i| r.push(i));
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), [3, 4, 5]);
        assert_eq!(r.len(), 3);
    }
}
