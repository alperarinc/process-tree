//! Bottom detail panel: files & sockets, libraries, threads, network for the selected process.
//! Fetches run on short-lived worker threads (one backend call per lock); results arrive over a channel.
use super::SharedBackend;
use crate::fmt;
use crate::model::{DetailError, FdEntry, Pid, ProcInfo, Proto, ThreadEntry};
use eframe::egui::{self, Align, Layout};
use egui_extras::{Column, TableBuilder};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

type Key = (Pid, u64);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Files,
    Libs,
    Threads,
    Net,
}

const TABS: [(Tab, &str); 4] = [(Tab::Files, "Files & Sockets"), (Tab::Libs, "Libraries"), (Tab::Threads, "Threads"), (Tab::Net, "Network")];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Fds,
    Libs,
    Threads,
}

impl Tab {
    fn kind(self) -> Kind {
        match self {
            Tab::Files | Tab::Net => Kind::Fds,
            Tab::Libs => Kind::Libs,
            Tab::Threads => Kind::Threads,
        }
    }
}

enum Data {
    Fds(Vec<FdEntry>),
    Libs(Vec<String>),
    Threads(Vec<ThreadEntry>),
}

struct Msg {
    key: Key,
    kind: Kind,
    res: Result<Data, DetailError>,
}

pub struct Details {
    pub visible: bool,
    tab: Tab,
    /// What `result` belongs to; a change resets it so stale rows never show.
    shown: Option<(Key, Kind)>,
    result: Option<Result<Data, DetailError>>,
    pending: Option<(Key, Kind)>,
    last: Option<Instant>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl Default for Details {
    fn default() -> Self {
        let (tx, rx) = channel();
        Self { visible: false, tab: Tab::Files, shown: None, result: None, pending: None, last: None, tx, rx }
    }
}

fn proto_name(p: &Proto) -> &'static str {
    match p {
        Proto::Tcp4 => "TCP",
        Proto::Tcp6 => "TCP6",
        Proto::Udp4 => "UDP",
        Proto::Udp6 => "UDP6",
        Proto::Unix => "Unix",
        Proto::Other => "—",
    }
}

fn is_net(e: &FdEntry) -> bool {
    matches!(e, FdEntry::Socket { proto: Proto::Tcp4 | Proto::Tcp6 | Proto::Udp4 | Proto::Udp6, .. })
}

fn fd_cells(e: &FdEntry) -> [String; 3] {
    match e {
        FdEntry::File { fd, path } => [fd.to_string(), "Dosya".into(), path.clone()],
        FdEntry::Socket { fd, proto, local, remote, state } => {
            [fd.to_string(), "Soket".into(), format!("{} {local} → {remote} {state}", proto_name(proto))]
        }
        FdEntry::Pipe { fd } => [fd.to_string(), "Pipe".into(), "—".into()],
        FdEntry::Other { fd, kind } => [fd.to_string(), "Other".into(), kind.clone()],
    }
}

fn net_cells(e: &FdEntry) -> [String; 4] {
    match e {
        FdEntry::Socket { proto, local, remote, state, .. } => [proto_name(proto).into(), local.clone(), remote.clone(), state.clone()],
        _ => Default::default(),
    }
}

fn grid(ui: &mut egui::Ui, heads: &[&str], n: usize, cell: impl Fn(usize, usize) -> String) {
    let mut tb = TableBuilder::new(ui).striped(true).auto_shrink(false).cell_layout(Layout::left_to_right(Align::Center));
    for (i, _) in heads.iter().enumerate() {
        tb = tb.column(if i + 1 == heads.len() { Column::remainder().clip(true) } else { Column::auto().at_least(60.0).clip(true) });
    }
    tb.header(20.0, |mut h| {
        for t in heads {
            h.col(|ui| {
                ui.strong(*t);
            });
        }
    })
    .body(|body| {
        body.rows(18.0, n, |mut row| {
            let i = row.index();
            for c in 0..heads.len() {
                row.col(|ui| {
                    ui.add(egui::Label::new(cell(i, c)).truncate());
                });
            }
        });
    });
}

impl Details {
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
    }

    fn spawn(&self, backend: &SharedBackend, ctx: &egui::Context, key: Key, kind: Kind) {
        let (b, tx, ctx) = (backend.clone(), self.tx.clone(), ctx.clone());
        let _ = std::thread::Builder::new().name("detail".into()).spawn(move || {
            let res = match kind {
                Kind::Fds => b.lock().unwrap().open_fds(key.0).map(Data::Fds),
                Kind::Libs => b.lock().unwrap().mapped_files(key.0).map(Data::Libs),
                Kind::Threads => b.lock().unwrap().threads(key.0).map(Data::Threads),
            };
            let _ = tx.send(Msg { key, kind, res });
            ctx.request_repaint();
        });
    }

    pub fn show(&mut self, ui: &mut egui::Ui, backend: &SharedBackend, live: &HashMap<Pid, ProcInfo>, sel: Option<Key>, every: Duration) {
        ui.horizontal(|ui| {
            for (t, title) in TABS {
                ui.selectable_value(&mut self.tab, t, title);
            }
        });
        ui.separator();
        let kind = self.tab.kind();
        while let Ok(m) = self.rx.try_recv() {
            if self.pending == Some((m.key, m.kind)) {
                self.pending = None;
            }
            // Drop results for a different selection/tab (also keeps the pending slot honest).
            if Some((m.key, m.kind)) == self.shown {
                self.result = Some(m.res);
                self.last = Some(Instant::now());
            }
        }
        let Some(key) = sel else {
            self.shown = None;
            self.result = None;
            return msg(ui, "Select a process");
        };
        if self.shown != Some((key, kind)) {
            self.shown = Some((key, kind));
            self.result = None;
            self.last = None;
        }
        if live.get(&key.0).is_none_or(|p| p.start_time != key.1) {
            self.result = None;
            return msg(ui, &DetailError::NoSuchProcess.to_string());
        }
        if self.last.is_none_or(|t| t.elapsed() >= every / 2) && self.pending != Some((key, kind)) {
            self.pending = Some((key, kind));
            self.spawn(backend, ui.ctx(), key, kind);
        }
        match (&self.result, self.tab) {
            (None, _) => msg(ui, "Loading…"),
            (Some(Err(e)), _) => msg(ui, &e.to_string()),
            (Some(Ok(Data::Fds(v))), Tab::Net) => {
                let s: Vec<_> = v.iter().filter(|e| is_net(e)).map(net_cells).collect();
                grid(ui, &["Protocol", "Local", "Remote", "State"], s.len(), |i, c| s[i][c].clone());
            }
            (Some(Ok(Data::Fds(v))), _) => {
                grid(ui, &["FD", "Type", "Detail"], v.len(), |i, c| std::mem::take(&mut fd_cells(&v[i])[c]));
            }
            (Some(Ok(Data::Libs(v))), _) => grid(ui, &["Path"], v.len(), |i, _| v[i].clone()),
            (Some(Ok(Data::Threads(v))), _) => grid(ui, &["ID", "Ad", "CPU %", "State"], v.len(), |i, c| {
                let t = &v[i];
                match c {
                    0 => t.id.to_string(),
                    1 => t.name.clone(),
                    2 => fmt::pct(t.cpu),
                    _ => t.state.clone(),
                }
            }),
        }
    }
}

fn msg(ui: &mut egui::Ui, text: &str) {
    ui.centered_and_justified(|ui| {
        ui.label(text);
    });
}
