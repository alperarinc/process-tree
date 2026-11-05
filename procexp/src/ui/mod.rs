//! eframe app: sampler thread, toolbar, process table, confirmation dialogs, status bar.
pub mod details;
pub mod properties;
pub mod toolbar;
pub mod tree_view;

use crate::actions;
use crate::backend::{Backend, LocalBackend};
use crate::darwin::windows;
use crate::helper::{self, HelperClient};
use crate::lifecycle::Tracker;
use crate::metacache::MetaCache;
use crate::model::{DetailError, Pid, ProcInfo, Sig, Snapshot};
use crate::settings::{self, Column, Settings};
use crate::tree::descendants_postorder;
use crate::vt::{self, UreqHttp, VtService};
use eframe::egui;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::{Arc, Condvar, Mutex};
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

/// A sleep that `wake` cuts short (sticky: a wake before `wait` makes it return at once).
#[derive(Default)]
struct Waker {
    flag: Mutex<bool>,
    cv: Condvar,
}

impl Waker {
    fn wait(&self, d: Duration) {
        let mut g = self.cv.wait_timeout_while(self.flag.lock().unwrap(), d, |f| !*f).unwrap().0;
        *g = false;
    }
    fn wake(&self) {
        *self.flag.lock().unwrap() = true;
        self.cv.notify_all();
    }
}

/// Tree kill from pid <= 1 (kernel_task / launchd) would hit nearly every process.
pub fn tree_kill_allowed(pid: Pid) -> bool {
    pid > 1
}

/// Duraklat on our own pid would freeze the UI beyond recovery.
pub fn pause_allowed(pid: Pid) -> bool {
    pid != std::process::id() as Pid
}

/// Samples every `every_ms` (re-read each round), hands the snapshot to the UI and wakes it; exits when the UI is gone.
fn spawn_sampler(backend: SharedBackend, ctx: egui::Context, every_ms: Arc<AtomicU64>, waker: Arc<Waker>) -> Receiver<Result<Snapshot, DetailError>> {
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name("sampler".into())
        .spawn(move || loop {
            let r = backend.lock().unwrap().sample();
            if tx.send(r).is_err() {
                return;
            }
            ctx.request_repaint();
            waker.wait(Duration::from_millis(every_ms.load(Ordering::Relaxed)));
        })
        .expect("spawn sampler");
    rx
}

/// Children first, root last; only pids in `live`, each with its own start time. Absent root → empty.
pub fn kill_tree_targets(live: &HashMap<Pid, ProcInfo>, root: Pid) -> Vec<(Pid, u64)> {
    // descendants_postorder returns [root] even when root is absent; the filter drops it.
    descendants_postorder(live, root).iter().filter_map(|q| live.get(q)).map(|q| (q.pid, q.start_time)).collect()
}

const ADMIN_CANCELLED: &str = "Admin mode cancelled";

/// prepare_dir → `launch` (blocks on the password prompt) → `connect`. On failure removes the temp
/// dir and token itself: the client only cleans up once it exists.
fn elevate(
    launch: impl FnOnce(&Path) -> io::Result<()>,
    connect: impl FnOnce(&Path, &str) -> io::Result<HelperClient>,
) -> Result<HelperClient, String> {
    let fail = |e: io::Error| format!("Could not start admin mode: {e}");
    let (dir, token) = helper::prepare_dir().map_err(fail)?;
    // osascript reports a cancelled prompt only as a non-zero exit, so any launch error reads as cancel.
    let r = match launch(&dir) {
        Err(_) => Err(ADMIN_CANCELLED.to_string()),
        Ok(()) => connect(&dir, &token).map_err(fail),
    };
    if r.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    r
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
    ctx: egui::Context,
    details: details::Details,
    props: properties::Props,
    proc_hist: properties::ProcHistory,
    /// Sampler interval, shared with the sampler thread.
    interval: Arc<AtomicU64>,
    /// Cuts the sampler's sleep short (refocus, interval change).
    waker: Arc<Waker>,
    was_focused: bool,
    /// The helper backend is installed.
    admin: bool,
    /// Elevation in progress on a worker thread.
    admin_rx: Option<Receiver<Result<HelperClient, String>>>,
    /// Nişangâh drag in progress.
    picking: bool,
    settings_open: bool,
    /// API key edited but not yet applied (applied when the field loses focus).
    key_dirty: bool,
    vt: Option<VtService>,
}

impl App {
    fn new(ctx: &egui::Context) -> Self {
        let settings_path = settings::app_support_dir().join("settings.json");
        let mut settings = settings::load(&settings_path);
        // A hand-edited 0 would make the sampler spin.
        settings.interval_ms = settings.interval_ms.clamp(500, 5000);
        let backend: SharedBackend = Arc::new(Mutex::new(Box::new(LocalBackend::new())));
        let interval = Arc::new(AtomicU64::new(settings.interval_ms));
        let waker = Arc::new(Waker::default());
        let rx = spawn_sampler(backend.clone(), ctx.clone(), interval.clone(), waker.clone());
        let c = ctx.clone();
        let mut app = Self {
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
            ctx: ctx.clone(),
            details: Default::default(),
            props: Default::default(),
            proc_hist: Default::default(),
            interval,
            waker,
            was_focused: true,
            admin: false,
            admin_rx: None,
            picking: false,
            settings_open: false,
            key_dirty: false,
            vt: None,
        };
        app.sync_vt();
        app
    }

    /// Start or stop the VirusTotal service to match the settings; no service (no network) unless on with a key.
    fn sync_vt(&mut self) {
        let on = self.settings.vt_enabled && !self.settings.vt_api_key.is_empty();
        match (&self.vt, on) {
            (None, true) => {
                let c = self.ctx.clone();
                let s = VtService::new(vt::default_cache_path(), Box::new(UreqHttp), self.settings.vt_api_key.clone(), Box::new(move || c.request_repaint()));
                for p in self.live.values() {
                    if let Some(e) = &p.exe {
                        s.enqueue(e);
                    }
                }
                self.vt = Some(s);
            }
            (Some(s), true) => s.set_key(self.settings.vt_api_key.clone()),
            (Some(_), false) => self.vt = None,
            (None, false) => {}
        }
    }

    fn set_column(&mut self, c: Column, on: bool) {
        let mut cols: Vec<_> = self.settings.columns.iter().copied().filter(|&x| x != c).collect();
        if on {
            cols.push(c);
        }
        self.settings.columns = tree_view::ALL_COLUMNS.into_iter().filter(|c| cols.contains(c)).collect();
    }

    fn start_admin(&mut self) {
        let (tx, rx) = channel();
        let ctx = self.ctx.clone();
        std::thread::Builder::new()
            .name("elevate".into())
            .spawn(move || {
                let r = elevate(
                    |d| helper::launch(&std::env::current_exe()?, d),
                    |d, t| HelperClient::connect(d, t, Duration::from_secs(30)),
                );
                let _ = tx.send(r);
                ctx.request_repaint();
            })
            .expect("spawn elevate");
        self.admin_rx = Some(rx);
    }

    /// Any `Disconnected` while in Yönetici modu: back to the local backend. Sampler and detail
    /// workers lock the shared slot per call, so they simply use the new backend on their next call.
    fn on_error(&mut self, e: &DetailError) {
        if self.admin && matches!(e, DetailError::Disconnected) {
            *self.backend.lock().unwrap() = Box::new(LocalBackend::new());
            self.admin = false;
            self.status = Some("Admin connection lost — back to normal mode".into());
        }
    }

    /// Nişangâh released: select the process owning the front-most window under the mouse.
    fn pick(&mut self) {
        let (x, y) = windows::global_mouse();
        let own = std::process::id() as Pid;
        // -1 excludes nothing: our own window in front counts as a miss, not the window behind it.
        let hit = windows::pick_window(&windows::on_screen_windows(), x, y, -1).filter(|&p| p != own);
        match hit.and_then(|pid| self.live.get(&pid)) {
            Some(p) => {
                let (pid, start) = (p.pid, p.start_time);
                self.tree.reveal(pid, start, &self.live);
                self.status = None;
            }
            None => self.status = Some("No window found".into()),
        }
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.settings_open;
        let (mut save, mut vt_changed) = (false, false);
        egui::Window::new("Settings").open(&mut open).resizable(false).collapsible(false).show(ctx, |ui| {
            let r = ui.add(egui::Slider::new(&mut self.settings.interval_ms, 500..=5000).text("Refresh interval").suffix(" ms"));
            if r.changed() {
                self.interval.store(self.settings.interval_ms, Ordering::Relaxed);
            }
            save |= r.drag_stopped() || (r.changed() && !r.dragged());
            if save {
                self.waker.wake();
            }
            ui.separator();
            vt_changed |= ui.checkbox(&mut self.settings.vt_enabled, "VirusTotal checks").changed();
            ui.small("Only file hashes (SHA-256) are sent.");
            ui.horizontal(|ui| {
                ui.label("API key");
                let r = ui.add(egui::TextEdit::singleline(&mut self.settings.vt_api_key).password(true).desired_width(260.0));
                self.key_dirty |= r.changed();
                if r.lost_focus() && std::mem::take(&mut self.key_dirty) {
                    vt_changed = true;
                }
            });
        });
        if !open && std::mem::take(&mut self.key_dirty) {
            vt_changed = true;
        }
        if vt_changed {
            let had = self.vt.is_some();
            self.sync_vt();
            if had != self.vt.is_some() {
                self.set_column(Column::Vt, self.vt.is_some());
            }
        }
        if save || vt_changed {
            self.save_settings();
        }
        self.settings_open = open;
    }

    fn save_settings(&mut self) {
        if let Err(e) = self.settings.save(&self.settings_path) {
            self.status = Some(format!("Could not save settings: {e}"));
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
        if let Some((_, _, e)) = errs.iter().find(|(_, _, e)| matches!(e, DetailError::Disconnected)) {
            let e = e.clone();
            self.on_error(&e);
            return;
        }
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
                if tree && !tree_kill_allowed(pid) {
                    self.status = Some("Kill process tree is disabled for this process".into());
                    return;
                }
                let targets = if tree { kill_tree_targets(&self.live, pid) } else { vec![(pid, p.start_time)] };
                let text = if tree {
                    format!("Kill {} ({pid}) and {} child processes?", p.name, targets.len() - 1)
                } else {
                    format!("Kill {} ({pid})?", p.name)
                };
                self.confirm = Some(Confirm { text, targets, sig });
            }
            Action::Signal { pid, sig: Sig::Stop, .. } if !pause_allowed(pid) => {
                self.status = Some("The app can't suspend itself".into());
            }
            Action::Signal { pid, start, sig } => self.signal(&[(pid, start)], sig),
            Action::Nice { pid, start } => self.nice = Some(Nice { pid, start, value: 0 }),
            Action::Properties { pid, start } => {
                if let Some(p) = self.view.get(&pid).filter(|p| p.start_time == start) {
                    let name = p.name.clone();
                    self.props.open(&self.backend, &self.ctx, (pid, start), name);
                }
            }
            Action::Reveal(path) => {
                if let Err(e) = actions::reveal_in_finder(&path) {
                    self.status = Some(e.to_string());
                }
            }
            Action::ToggleColumn(c) => {
                self.set_column(c, !self.settings.columns.contains(&c));
                self.save_settings();
            }
            Action::VtCheck(exe) => {
                if let Some(s) = &self.vt {
                    s.prioritize(&exe);
                }
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
                    go = ui.button("Terminate").clicked();
                    cancel = ui.button("Cancel").clicked();
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
                ui.label(format!("Priority — {} ({})", self.view.get(&n.pid).map_or("?", |p| p.name.as_str()), n.pid));
                ui.add(egui::Slider::new(&mut n.value, -20..=20));
                ui.horizontal(|ui| {
                    go = ui.button("Uygula").clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
            if go {
                let n = self.nice.take().unwrap();
                let r = self.backend.lock().unwrap().renice(n.pid, n.start, n.value);
                if let Err(e) = r {
                    self.status = Some(format!("{} ({}): {e}", self.name(n.pid), n.pid));
                    self.on_error(&e);
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
                    properties::record(&mut self.proc_hist, &snap.procs, &self.view);
                    if let Some(vt) = &self.vt {
                        // enqueue is a no-op for paths it has seen, so new processes are picked up here.
                        for e in snap.procs.values().filter_map(|p| p.exe.as_deref()) {
                            vt.enqueue(e);
                        }
                    }
                    self.live = snap.procs;
                }
                Err(e) => {
                    self.status = Some(e.to_string());
                    self.on_error(&e);
                }
            }
        }
        let got = self.admin_rx.as_ref().map(|rx| rx.try_recv());
        if let Some(r) = got.filter(|r| !matches!(r, Err(TryRecvError::Empty))) {
            self.admin_rx = None;
            match r.unwrap_or_else(|_| Err("Could not start admin mode".into())) {
                Ok(c) => {
                    *self.backend.lock().unwrap() = Box::new(c);
                    self.admin = true;
                    self.status = None;
                    self.props.retry_denied(&self.backend, &self.ctx);
                }
                Err(msg) => self.status = Some(msg),
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let minimized = ctx.input(|i| i.viewport().minimized).unwrap_or(false);
        // Unfocused: sample at least every 5 s, to stay under the 2 % background CPU budget.
        let focused = ctx.input(|i| i.focused);
        let want = if focused { self.settings.interval_ms } else { self.settings.interval_ms.max(5000) };
        self.interval.store(want, Ordering::Relaxed);
        if focused && !self.was_focused {
            self.waker.wake();
        }
        self.was_focused = focused;
        let mut bar = toolbar::Out::default();
        egui::Panel::top("toolbar").show(ui, |ui| {
            bar = toolbar::show(ui, &self.history, &mut self.query, &mut self.settings.flat, self.admin, self.admin_rx.is_some());
        });
        if bar.mode_changed {
            self.save_settings();
        }
        if bar.admin {
            self.start_admin();
        }
        if bar.settings {
            self.settings_open = true;
        }
        self.picking |= bar.pick;
        if self.picking {
            ctx.set_cursor_icon(egui::CursorIcon::Crosshair);
            if windows::left_mouse_down() {
                // Polling the global button state needs frames while the mouse is outside our window.
                ctx.request_repaint();
            } else {
                self.picking = false;
                self.pick();
            }
        }
        egui::Panel::bottom("status").show(ui, |ui| {
            let text = if self.admin_rx.is_some() { Some("Waiting for admin mode…".to_string()) } else { self.status.clone() };
            ui.label(text.unwrap_or_else(|| format!("{} processes", self.live.len())));
        });
        let mut act = None;
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::L)) {
            self.details.toggle();
        }
        if self.details.visible {
            let every = Duration::from_millis(want);
            egui::Panel::bottom("details").resizable(true).default_size(220.0).show(ui, |ui| {
                self.details.show(ui, &self.backend, &self.live, self.tree.selected, every);
            });
        }
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
                    vt: self.vt.as_ref(),
                },
            );
        });
        if let Some(a) = act {
            self.handle(a);
        }
        let out = self.props.show(&ctx, &self.live, &self.view, &self.proc_hist, &self.meta);
        if out.select.is_some() {
            self.tree.selected = out.select;
        }
        if let Some(p) = out.reveal {
            self.handle(Action::Reveal(p));
        }
        self.settings_window(&ctx);
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
    fn elevate_removes_temp_dir_when_cancelled_or_connect_fails() {
        let seen = std::cell::RefCell::new(None);
        let r = elevate(
            |d| {
                assert!(d.join("token").exists());
                *seen.borrow_mut() = Some(d.to_path_buf());
                Err(io::Error::other("osascript: exit status: 1"))
            },
            |_, _| unreachable!("no connect after a cancelled prompt"),
        );
        assert_eq!(r.err().as_deref(), Some(ADMIN_CANCELLED));
        assert!(!seen.borrow().as_ref().unwrap().exists());

        let r = elevate(
            |d| {
                *seen.borrow_mut() = Some(d.to_path_buf());
                std::fs::write(d.join("sock"), "").unwrap(); // stands in for the helper's socket
                Ok(())
            },
            |_, _| Err(io::ErrorKind::TimedOut.into()),
        );
        assert!(r.err().unwrap().starts_with("Could not start admin mode"));
        assert!(!seen.borrow().as_ref().unwrap().exists());
    }

    #[test]
    fn waker_wakes_early_and_is_sticky() {
        let w = Arc::new(Waker::default());
        let w2 = w.clone();
        let t = Instant::now();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            w2.wake();
        });
        w.wait(Duration::from_secs(10));
        assert!(t.elapsed() < Duration::from_secs(2));
        h.join().unwrap();
        w.wake(); // wake before wait still returns at once
        let t = Instant::now();
        w.wait(Duration::from_secs(10));
        assert!(t.elapsed() < Duration::from_secs(2));
        let t = Instant::now();
        w.wait(Duration::from_millis(50)); // flag was consumed: times out normally
        assert!(t.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn kill_tree_and_pause_gates() {
        assert!(!tree_kill_allowed(0) && !tree_kill_allowed(1) && tree_kill_allowed(2));
        let own = std::process::id() as Pid;
        assert!(!pause_allowed(own) && pause_allowed(own + 1));
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
