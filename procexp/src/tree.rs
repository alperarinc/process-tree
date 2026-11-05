use crate::model::*;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

pub struct Row {
    pub pid: Pid,
    pub depth: u16,
    pub has_children: bool,
}

pub struct ViewOpts<'a> {
    pub collapsed: &'a HashSet<Pid>,
    pub query: &'a str,
    pub flat: bool,
}

/// None if ppid is missing from the snapshot or equals the pid itself.
pub fn parent_of(p: &ProcInfo, procs: &HashMap<Pid, ProcInfo>) -> Option<Pid> {
    (p.ppid != p.pid && procs.contains_key(&p.ppid)).then_some(p.ppid)
}

fn matches(p: &ProcInfo, q: &str) -> bool {
    q.is_empty()
        || p.name.to_lowercase().contains(q)
        || p.exe
            .as_ref()
            .is_some_and(|e| e.to_string_lossy().to_lowercase().contains(q))
        || q.parse::<Pid>() == Ok(p.pid)
}

fn reaches_root(mut pid: Pid, procs: &HashMap<Pid, ProcInfo>, limit: usize) -> bool {
    for _ in 0..=limit {
        match parent_of(&procs[&pid], procs) {
            None => return true,
            Some(par) => pid = par,
        }
    }
    false
}

fn children_map(procs: &HashMap<Pid, ProcInfo>, keep: &HashSet<Pid>) -> HashMap<Pid, Vec<Pid>> {
    let mut m: HashMap<Pid, Vec<Pid>> = HashMap::new();
    for &pid in keep {
        if let Some(par) = parent_of(&procs[&pid], procs) {
            m.entry(par).or_default().push(pid);
        }
    }
    m
}

pub fn build_rows(
    procs: &HashMap<Pid, ProcInfo>,
    opts: &ViewOpts,
    cmp: &dyn Fn(&ProcInfo, &ProcInfo) -> Ordering,
) -> Vec<Row> {
    let q = opts.query.trim().to_lowercase();
    let hits: HashSet<Pid> = procs
        .values()
        .filter(|p| matches(p, &q))
        .map(|p| p.pid)
        .collect();
    let sort = |v: &mut Vec<Pid>| v.sort_by(|a, b| cmp(&procs[a], &procs[b]).then(a.cmp(b)));

    if opts.flat {
        let mut v: Vec<Pid> = hits.into_iter().collect();
        sort(&mut v);
        return v
            .into_iter()
            .map(|pid| Row {
                pid,
                depth: 0,
                has_children: false,
            })
            .collect();
    }

    // Matches plus all their ancestors; the visited check stops ppid cycles.
    let mut keep = hits.clone();
    for &pid in &hits {
        let mut cur = pid;
        while let Some(par) = parent_of(&procs[&cur], procs) {
            // Already kept: its own ancestors are handled by its own iteration.
            if !keep.insert(par) {
                break;
            }
            cur = par;
        }
    }

    let mut kids = children_map(procs, &keep);
    for v in kids.values_mut() {
        sort(v);
    }
    let mut roots: Vec<Pid> = keep
        .iter()
        .copied()
        .filter(|pid| parent_of(&procs[pid], procs).is_none())
        .collect();
    sort(&mut roots);

    let mut out = Vec::with_capacity(keep.len());
    let mut seen = HashSet::new();
    let mut walk = |root: Pid, out: &mut Vec<Row>| {
        let mut stack = vec![(root, 0u16)];
        while let Some((pid, depth)) = stack.pop() {
            if !seen.insert(pid) {
                continue;
            }
            let ch = kids.get(&pid).map(Vec::as_slice).unwrap_or(&[]);
            out.push(Row {
                pid,
                depth,
                has_children: !ch.is_empty(),
            });
            if !opts.collapsed.contains(&pid) {
                stack.extend(ch.iter().rev().map(|&c| (c, depth.saturating_add(1))));
            }
        }
    };
    for r in roots {
        walk(r, &mut out);
    }
    // Members of a pure ppid cycle have no root; surface one per cycle.
    let mut cyclic: Vec<Pid> = keep
        .iter()
        .copied()
        .filter(|&pid| !reaches_root(pid, procs, keep.len()))
        .collect();
    sort(&mut cyclic);
    for pid in cyclic {
        walk(pid, &mut out);
    }
    out
}

/// Postorder: children before parents, root last. Cycle-safe.
pub fn descendants_postorder(procs: &HashMap<Pid, ProcInfo>, root: Pid) -> Vec<Pid> {
    let keep: HashSet<Pid> = procs.keys().copied().collect();
    let mut kids = children_map(procs, &keep);
    for v in kids.values_mut() {
        v.sort_unstable();
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![(root, false)];
    while let Some((pid, done)) = stack.pop() {
        if done {
            out.push(pid);
        } else if seen.insert(pid) {
            stack.push((pid, true));
            stack.extend(
                kids.get(&pid)
                    .into_iter()
                    .flatten()
                    .rev()
                    .map(|&c| (c, false)),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: Pid, ppid: Pid, name: &str) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            name: name.into(),
            exe: Some(format!("/bin/{name}").into()),
            user: "u".into(),
            uid: 0,
            cpu: 0.0,
            mem: 0,
            threads: None,
            status: ProcStatus::Running,
            start_time: 0,
            disk_read: 0,
            disk_write: 0,
        }
    }
    fn fixture() -> HashMap<Pid, ProcInfo> {
        let mut m = HashMap::new();
        for x in [
            p(0, 0, "kernel_task"),
            p(1, 0, "launchd"),
            p(10, 1, "zsh"),
            p(11, 10, "vim"),
            p(20, 1, "Finder"),
        ] {
            m.insert(x.pid, x);
        }
        m
    }
    fn by_pid(a: &ProcInfo, b: &ProcInfo) -> Ordering {
        a.pid.cmp(&b.pid)
    }
    fn rows(
        f: &HashMap<Pid, ProcInfo>,
        collapsed: &[Pid],
        query: &str,
        flat: bool,
        cmp: &dyn Fn(&ProcInfo, &ProcInfo) -> Ordering,
    ) -> Vec<Row> {
        let c: HashSet<Pid> = collapsed.iter().copied().collect();
        build_rows(
            f,
            &ViewOpts {
                collapsed: &c,
                query,
                flat,
            },
            cmp,
        )
    }
    fn pids(r: &[Row]) -> Vec<Pid> {
        r.iter().map(|x| x.pid).collect()
    }
    fn depths(r: &[Row]) -> Vec<u16> {
        r.iter().map(|x| x.depth).collect()
    }

    #[test]
    fn tree_order_by_pid() {
        let r = rows(&fixture(), &[], "", false, &by_pid);
        assert_eq!(pids(&r), [0, 1, 10, 11, 20]);
        assert_eq!(depths(&r), [0, 1, 2, 3, 2]);
        assert!(r[1].has_children && !r[3].has_children);
    }
    #[test]
    fn collapse_hides_children() {
        assert_eq!(
            pids(&rows(&fixture(), &[10], "", false, &by_pid)),
            [0, 1, 10, 20]
        );
    }
    #[test]
    fn filter_keeps_ancestors() {
        let f = fixture();
        assert_eq!(pids(&rows(&f, &[], "VIM", false, &by_pid)), [0, 1, 10, 11]);
        assert_eq!(pids(&rows(&f, &[], "20", false, &by_pid)), [0, 1, 20]);
    }
    #[test]
    fn siblings_follow_comparator() {
        let mut f = fixture();
        f.get_mut(&20).unwrap().cpu = 50.0;
        f.get_mut(&10).unwrap().cpu = 1.0;
        let cpu_desc = |a: &ProcInfo, b: &ProcInfo| b.cpu.total_cmp(&a.cpu);
        assert_eq!(
            pids(&rows(&f, &[], "", false, &cpu_desc)),
            [0, 1, 20, 10, 11]
        );
    }
    #[test]
    fn flat_mode_sorts_everything() {
        let desc = |a: &ProcInfo, b: &ProcInfo| b.pid.cmp(&a.pid);
        let r = rows(&fixture(), &[1], "", true, &desc);
        assert_eq!(pids(&r), [20, 11, 10, 1, 0]);
        assert!(depths(&r).iter().all(|&d| d == 0));
    }
    #[test]
    fn orphans_and_self_parent_are_roots() {
        let mut f = fixture();
        for x in [
            p(50, 999, "orphan"),
            p(60, 60, "self"),
            p(70, 71, "a"),
            p(71, 70, "b"),
        ] {
            f.insert(x.pid, x);
        }
        let r = rows(&f, &[], "", false, &by_pid);
        let mut got = pids(&r);
        got.sort();
        assert_eq!(got, [0, 1, 10, 11, 20, 50, 60, 70, 71]);
        for want in [50, 60] {
            assert_eq!(r.iter().find(|x| x.pid == want).unwrap().depth, 0);
        }
    }
    #[test]
    fn no_exe_is_fine() {
        let mut f = fixture();
        let mut z = p(99, 1, "");
        z.exe = None;
        f.insert(99, z);
        assert!(pids(&rows(&f, &[], "", false, &by_pid)).contains(&99));
        assert!(pids(&rows(&f, &[], "x", false, &by_pid)).is_empty());
    }
    #[test]
    fn descendants_children_first() {
        assert_eq!(descendants_postorder(&fixture(), 1), [11, 10, 20, 1]);
    }
    #[test]
    fn parent_of_rules() {
        let f = fixture();
        assert_eq!(parent_of(&f[&11], &f), Some(10));
        assert_eq!(parent_of(&f[&0], &f), None);
        assert_eq!(parent_of(&p(5, 999, "x"), &f), None);
    }
}
