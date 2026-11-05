//! eframe app: sampler thread, toolbar, process table, confirmation dialogs, status bar.
pub mod toolbar;
pub mod tree_view;

use crate::actions;
use crate::backend::{Backend, LocalBackend};
use crate::lifecycle::Tracker;
use crate::metacache::MetaCache;
use crate::model::{DetailError, Pid, ProcInfo, Sig, Snapshot};
use crate::settings::{self, Settings};
use crate::tree::descendants_postorder;
use eframe::egui;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tree_view::{Action, TreeView, View};

type SharedBackend = Arc<Mutex<Box<dyn Backend>>>;

pub fn run() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("Process Tree").with_inner_size([1150.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native("Process Tree", opts, Box::new(|cc| Ok(Box::new(App::new(&cc.egui_ctx)))))
}

/// Samples every `every`, hands the snapshot to the UI and wakes it; exits when the UI is gone.
fn spawn_sampler(backend: SharedBackend, ctx: egui::Context, every: Duration) -> Receiver<Result<Snapshot, DetailError>> {
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name("sampler".into())
        .spawn(move || loop {
            let r = backend.lock().unwrap().sample();
            if tx.send(r).is_err() {
                return;
            }
            ctx.request_repaint();
            std::thread::sleep(every);
        })
        .expect("spawn sampler");
    rx
}

/// Children first, root last; only pids in `live`, each with its own start time. Absent root → empty.
pub fn kill_tree_targets(live: &HashMap<Pid, ProcInfo>, root: Pid) -> Vec<(Pid, u64)> {
    // descendants_postorder returns [root] even when root is absent; the filter drops it.
    descendants_postorder(live, root).iter().filter_map(|q| live.get(q)).map(|q| (q.pid, q.start_time)).collect()
}

struct Confirm {
    text: String,
    targets: Vec<(Pid, u64)>,
    sig: Sig,
}

struct Nice {
    pid: Pid,
    start: u64,
    value: i32,
}

struct App {
    backend: SharedBackend,
    rx: Receiver<Result<Snapshot, DetailError>>,
    settings: Settings,
    settings_path: PathBuf,
    tracker: Tracker,
    history: toolbar::History,
    meta: MetaCache,
    /// Current snapshot (action targets).
    live: HashMap<Pid, ProcInfo>,
    /// `live` plus exited ghosts (display).
    view: HashMap<Pid, ProcInfo>,
    tree: TreeView,
    query: String,
    status: Option<String>,
    confirm: Option<Confirm>,
    nice: Option<Nice>,
}

impl App {
    fn new(ctx: &egui::Context) -> Self {
        let settings_path = settings::app_support_dir().join("settings.json");
        let settings = settings::load(&settings_path);
        let backend: SharedBackend = Arc::new(Mutex::new(Box::new(LocalBackend::new())));
        let rx = spawn_sampler(backend.clone(), ctx.clone(), Duration::from_millis(settings.interval_ms));
        let c = ctx.clone();
        Self {
            backend,
            rx,
            settings,
            settings_path,
            tracker: Tracker::new(Duration::from_secs(3)),
            history: toolbar::History::default(),
            meta: MetaCache::new(Box::new(move || c.request_repaint())),
            live: HashMap::new(),
            view: HashMap::new(),
            tree: TreeView::default(),
            query: String::new(),
            status: None,
            confirm: None,
            nice: None,
        }
    }

    fn save_settings(&mut self) {
        if let Err(e) = self.settings.save(&self.settings_path) {
            self.status = Some(format!("Ayarlar kaydedilemedi: {e}"));
        }
    }

    fn name(&self, pid: Pid) -> String {
        self.view.get(&pid).map_or_else(|| "?".into(), |p| p.name.clone())
    }

    /// Signals every target (root last); reports the first failure, ignoring descendants that already exited.
    fn signal(&mut self, targets: &[(Pid, u64)], sig: Sig) {
        let mut be = self.backend.lock().unwrap();
        let errs: Vec<_> = targets
            .iter()
            .enumerate()
            .filter_map(|(i, &(pid, start))| be.signal(pid, start, sig.clone()).err().map(|e| (i, pid, e)))
            .collect();
        drop(be);
        let root = targets.len().saturating_sub(1);
        let err = errs.into_iter().find(|(i, _, e)| *i == root || !matches!(e, DetailError::NoSuchProcess)).map(|(_, pid, e)| (pid, e));
        self.status = err.map(|(pid, e)| format!("{} ({pid}): {e}", self.name(pid)));
    }

    fn handle(&mut self, a: Action) {
        self.status = None;
        match a {
            Action::Kill { pid, sig, tree } => {
                let Some(p) = self.live.get(&pid) else {
                    self.status = Some(format!("{} ({pid}): {}", self.name(pid), DetailError::NoSuchProcess));
                    return;
                };
                let targets = if tree { kill_tree_targets(&self.live, pid) } else { vec![(pid, p.start_time)] };
                let text = if tree {
                    format!("{} ({pid}) ve {} alt süreç sonlandırılsın mı?", p.name, targets.len() - 1)
                } else {
                    format!("{} ({pid}) sonlandırılsın mı?", p.name)
                };
                self.confirm = Some(Confirm { text, targets, sig });
            }
            Action::Signal { pid, start, sig } => self.signal(&[(pid, start)], sig),
            Action::Nice { pid, start } => self.nice = Some(Nice { pid, start, value: 0 }),
            Action::Reveal(path) => {
                if let Err(e) = actions::reveal_in_finder(&path) {
                    self.status = Some(e.to_string());
                }
            }
            Action::ToggleColumn(c) => {
                let mut on: Vec<_> = self.settings.columns.clone();
                if let Some(i) = on.iter().position(|&x| x == c) {
                    on.remove(i);
                } else {
                    on.push(c);
                }
                self.settings.columns = tree_view::ALL_COLUMNS.into_iter().filter(|c| on.contains(c)).collect();
                self.save_settings();
            }
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if let Some(c) = &self.confirm {
            let (mut go, mut cancel) = (false, false);
            let r = egui::Modal::new(egui::Id::new("confirm")).show(ctx, |ui| {
                ui.label(&c.text);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    go = ui.button("Sonlandır").clicked();
                    cancel = ui.button("Vazgeç").clicked();
                });
            });
            if go {
                let c = self.confirm.take().unwrap();
                self.signal(&c.targets, c.sig);
            } else if cancel || r.should_close() {
                self.confirm = None;
            }
        }
        if let Some(n) = &mut self.nice {
            let (mut go, mut cancel) = (false, false);
            let r = egui::Modal::new(egui::Id::new("nice")).show(ctx, |ui| {
                ui.label(format!("Öncelik — {} ({})", self.view.get(&n.pid).map_or("?", |p| p.name.as_str()), n.pid));
                ui.add(egui::Slider::new(&mut n.value, -20..=20));
                ui.horizontal(|ui| {
                    go = ui.button("Uygula").clicked();
                    cancel = ui.button("Vazgeç").clicked();
                });
            });
            if go {
                let n = self.nice.take().unwrap();
                let r = self.backend.lock().unwrap().renice(n.pid, n.start, n.value);
                if let Err(e) = r {
                    self.status = Some(format!("{} ({}): {e}", self.name(n.pid), n.pid));
                }
            } else if cancel || r.should_close() {
                self.nice = None;
            }
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(r) = self.rx.try_recv() {
            match r {
                Ok(snap) => {
                    self.tracker.update(&snap, Instant::now());
                    self.history.push(&snap.system);
                    self.view = snap.procs.clone();
                    for g in self.tracker.ghosts() {
                        self.view.entry(g.pid).or_insert(g);
                    }
                    self.live = snap.procs;
                }
                Err(e) => self.status = Some(e.to_string()),
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let minimized = ctx.input(|i| i.viewport().minimized).unwrap_or(false);
        egui::Panel::top("toolbar").show(ui, |ui| {
            if toolbar::show(ui, &self.history, &mut self.query, &mut self.settings.flat) {
                self.save_settings();
            }
        });
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.label(self.status.clone().unwrap_or_else(|| format!("{} süreç", self.live.len())));
        });
        let mut act = None;
        egui::CentralPanel::default().show(ui, |ui| {
            act = self.tree.show(
                ui,
                &View {
                    procs: &self.view,
                    tracker: &self.tracker,
                    meta: &self.meta,
                    columns: &self.settings.columns,
                    query: &self.query,
                    flat: self.settings.flat,
                    load_meta: !minimized,
                    modal_open: self.confirm.is_some() || self.nice.is_some(),
                },
            );
        });
        if let Some(a) = act {
            self.handle(a);
        }
        self.dialogs(&ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProcStatus;

    fn p(pid: Pid, ppid: Pid, start: u64) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            name: "x".into(),
            exe: None,
            user: "u".into(),
            uid: 501,
            cpu: 0.0,
            mem: 0,
            threads: None,
            status: ProcStatus::Running,
            start_time: start,
            disk_read: 0,
            disk_write: 0,
        }
    }

    #[test]
    fn tree_kill_targets_only_live_with_own_start_time() {
        let live: HashMap<Pid, ProcInfo> = [p(10, 1, 100), p(11, 10, 111), p(12, 11, 122), p(13, 10, 133)]
            .into_iter()
            .map(|x| (x.pid, x))
            .collect();
        assert_eq!(kill_tree_targets(&live, 10), [(12, 122), (11, 111), (13, 133), (10, 100)]);
        assert!(kill_tree_targets(&live, 999).is_empty());
    }
}
