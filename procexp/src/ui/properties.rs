//! Per-process properties windows (one per (pid, start_time)) and the per-process CPU/memory history.
use super::SharedBackend;
use crate::lifecycle::Ring;
use crate::metacache::MetaCache;
use crate::model::{DetailError, Pid, ProcExtra, ProcInfo};
use eframe::egui::{self, Color32, Sense, Shape, Stroke};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

type Key = (Pid, u64);
const SAMPLES: usize = 120;

pub type ProcHistory = HashMap<Key, (Ring<f32>, Ring<u64>)>;

/// Appends one sample per live process; drops entries that are neither live nor ghosts (`view`).
pub fn record(hist: &mut ProcHistory, live: &HashMap<Pid, ProcInfo>, view: &HashMap<Pid, ProcInfo>) {
    for p in live.values() {
        let (c, m) = hist.entry((p.pid, p.start_time)).or_insert_with(|| (Ring::new(SAMPLES), Ring::new(SAMPLES)));
        c.push(p.cpu);
        m.push(p.mem);
    }
    hist.retain(|&(pid, st), _| view.get(&pid).is_some_and(|p| p.start_time == st));
}

struct Win {
    name: String,
    extra: Option<Result<ProcExtra, DetailError>>,
}

pub struct Props {
    wins: HashMap<Key, Win>,
    tx: Sender<(Key, Result<ProcExtra, DetailError>)>,
    rx: Receiver<(Key, Result<ProcExtra, DetailError>)>,
}

#[derive(Default)]
pub struct Out {
    /// Parent clicked: select this process in the tree.
    pub select: Option<Key>,
    pub reveal: Option<PathBuf>,
}

impl Default for Props {
    fn default() -> Self {
        let (tx, rx) = channel();
        Self { wins: HashMap::new(), tx, rx }
    }
}

fn local_time(secs: u64) -> String {
    // SAFETY: localtime_r/strftime write only into the locals passed; digits only, so locale-independent.
    unsafe {
        let t = secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return secs.to_string();
        }
        let mut buf = [0u8; 32];
        let n = libc::strftime(buf.as_mut_ptr().cast(), buf.len(), c"%Y-%m-%d %H:%M:%S".as_ptr(), &tm);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

fn graph(ui: &mut egui::Ui, title: &str, vals: &[f64], max: f64, colour: Color32) {
    ui.label(title);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width().min(420.0), 60.0), Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 2.0, ui.visuals().extreme_bg_color);
    if vals.len() >= 2 {
        let step = rect.width() / (SAMPLES - 1) as f32;
        let pts = vals
            .iter()
            .enumerate()
            .map(|(i, v)| egui::pos2(rect.right() - (vals.len() - 1 - i) as f32 * step, rect.bottom() - (*v / max).clamp(0.0, 1.0) as f32 * rect.height()))
            .collect();
        p.add(Shape::line(pts, Stroke::new(1.5, colour)));
    }
}

fn row(ui: &mut egui::Ui, k: &str, v: impl Into<egui::WidgetText>) {
    ui.label(k);
    ui.add(egui::Label::new(v).wrap());
    ui.end_row();
}

fn extra_text<T>(e: &Option<Result<ProcExtra, DetailError>>, f: impl Fn(&ProcExtra) -> Option<T>, show: impl Fn(T) -> String) -> String {
    match e {
        None => "Loading…".into(),
        Some(Err(err)) => err.to_string(),
        Some(Ok(x)) => f(x).map_or_else(|| "—".into(), show),
    }
}

impl Props {
    pub fn open(&mut self, backend: &SharedBackend, ctx: &egui::Context, key: Key, name: String) {
        if self.wins.contains_key(&key) {
            return;
        }
        self.wins.insert(key, Win { name, extra: None });
        self.fetch(backend, ctx, key);
    }

    fn fetch(&self, backend: &SharedBackend, ctx: &egui::Context, key: Key) {
        let (b, tx, ctx) = (backend.clone(), self.tx.clone(), ctx.clone());
        let _ = std::thread::Builder::new().name("props".into()).spawn(move || {
            let r = b.lock().unwrap().proc_extra(key.0);
            let _ = tx.send((key, r));
            ctx.request_repaint();
        });
    }

    /// Backend swapped (admin mode on): windows that were denied get a fresh `proc_extra`.
    pub fn retry_denied(&mut self, backend: &SharedBackend, ctx: &egui::Context) {
        for key in self.take_denied() {
            self.fetch(backend, ctx, key);
        }
    }

    fn take_denied(&mut self) -> Vec<Key> {
        let mut keys = vec![];
        for (&k, w) in &mut self.wins {
            if matches!(w.extra, Some(Err(DetailError::AccessDenied))) {
                w.extra = None;
                keys.push(k);
            }
        }
        keys
    }

    pub fn show(&mut self, ctx: &egui::Context, live: &HashMap<Pid, ProcInfo>, view: &HashMap<Pid, ProcInfo>, hist: &ProcHistory, meta: &MetaCache) -> Out {
        while let Ok((k, r)) = self.rx.try_recv() {
            if let Some(w) = self.wins.get_mut(&k) {
                w.extra = Some(r);
            }
        }
        let mut out = Out::default();
        self.wins.retain(|&key, w| {
            let mut open = true;
            egui::Window::new(format!("{} ({})", w.name, key.0))
                .id(egui::Id::new(("props", key)))
                .open(&mut open)
                .default_width(480.0)
                .show(ctx, |ui| match live.get(&key.0).filter(|p| p.start_time == key.1) {
                    None => {
                        ui.label("Process exited");
                    }
                    Some(p) => body(ui, p, w, view, hist.get(&key), meta, &mut out),
                });
            open
        });
        out
    }
}

fn body(ui: &mut egui::Ui, p: &ProcInfo, w: &Win, view: &HashMap<Pid, ProcInfo>, hist: Option<&(Ring<f32>, Ring<u64>)>, meta: &MetaCache, out: &mut Out) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading("General");
        egui::Grid::new("genel").num_columns(2).show(ui, |ui| {
            row(ui, "Path", p.exe.as_ref().map_or("—".into(), |e| e.to_string_lossy().into_owned()));
            row(ui, "Command line", extra_text(&w.extra, |x| Some(x.args.join(" ")), |s| s));
            row(ui, "Working directory", extra_text(&w.extra, |x| x.cwd.clone(), |s| s));
            row(ui, "Started", local_time(p.start_time));
            ui.label("Parent");
            match view.get(&p.ppid).filter(|q| q.pid != p.pid) {
                Some(q) => {
                    if ui.link(format!("{} ({})", q.name, q.pid)).clicked() {
                        out.select = Some((q.pid, q.start_time));
                    }
                }
                None => {
                    ui.label(format!("({})", p.ppid));
                }
            }
            ui.end_row();
            row(ui, "User", p.user.clone());
        });
        if ui.add_enabled(p.exe.is_some(), egui::Button::new("Reveal in Finder")).clicked() {
            out.reveal = p.exe.clone();
        }
        ui.separator();
        ui.heading("Environment");
        match &w.extra {
            None => {
                ui.label("Loading…");
            }
            Some(Err(e)) => {
                ui.label(e.to_string());
            }
            Some(Ok(x)) => {
                egui::ScrollArea::vertical().id_salt("env").max_height(150.0).show(ui, |ui| {
                    egui::Grid::new("env").striped(true).num_columns(2).show(ui, |ui| {
                        for (k, v) in &x.env {
                            ui.label(k);
                            ui.add(egui::Label::new(v).wrap());
                            ui.end_row();
                        }
                    });
                });
            }
        }
        ui.separator();
        ui.heading("Signature");
        let m = p.exe.as_deref().and_then(|e| meta.get(e));
        match m.as_deref() {
            None => {
                ui.label(if p.exe.is_some() { "Loading…" } else { "—" });
            }
            Some(m) => match &m.signing {
                None => {
                    ui.label("Unsigned");
                }
                Some(s) => {
                    let dash = |o: &Option<String>| o.clone().unwrap_or_else(|| "—".into());
                    egui::Grid::new("imza").num_columns(2).show(ui, |ui| {
                        row(ui, "Valid", if s.valid { "Yes" } else { "No" });
                        row(ui, "Signed by", dash(&s.authority));
                        row(ui, "Team ID", dash(&s.team_id));
                        row(ui, "Company", dash(&s.company));
                    });
                }
            },
        }
        ui.separator();
        ui.heading("Performance");
        if let Some((cpu, mem)) = hist {
            let c: Vec<f64> = cpu.iter().map(|&v| v as f64).collect();
            let m: Vec<f64> = mem.iter().map(|&v| v as f64).collect();
            graph(ui, "CPU %", &c, c.iter().cloned().fold(100.0, f64::max), Color32::from_rgb(90, 160, 255));
            graph(ui, "Memory", &m, m.iter().cloned().fold(1.0, f64::max), Color32::from_rgb(255, 170, 60));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_denied_resets_only_access_denied() {
        let mut p = Props::default();
        p.wins.insert((1, 1), Win { name: "a".into(), extra: Some(Err(DetailError::AccessDenied)) });
        p.wins.insert((2, 2), Win { name: "b".into(), extra: Some(Err(DetailError::NoSuchProcess)) });
        p.wins.insert((3, 3), Win { name: "c".into(), extra: None });
        assert_eq!(p.take_denied(), [(1, 1)]);
        assert!(p.wins[&(1, 1)].extra.is_none());
        assert!(matches!(p.wins[&(2, 2)].extra, Some(Err(DetailError::NoSuchProcess))));
    }
}
