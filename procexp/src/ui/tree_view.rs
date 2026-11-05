//! Process table: virtualized rows, sortable/hideable columns, lifecycle colours, keyboard, context menu.
use crate::fmt;
use crate::lifecycle::{Life, Tracker};
use crate::metacache::{Meta, MetaCache};
use crate::model::{Pid, ProcInfo, ProcStatus, Sig};
use crate::settings::Column;
use crate::tree::{build_rows, ViewOpts};
use crate::vt::{VtService, VtState};
use eframe::egui::{self, Align, Color32, Key, Label, Layout, RichText, Sense, TextureHandle};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

pub type MetaFn<'a> = dyn Fn(&ProcInfo) -> (Option<String>, Option<String>, Option<VtState>) + 'a;

pub const ALL_COLUMNS: [Column; 9] = [
    Column::Name,
    Column::Pid,
    Column::Cpu,
    Column::Mem,
    Column::Threads,
    Column::User,
    Column::Description,
    Column::Company,
    Column::Vt,
];

pub fn title(c: Column) -> &'static str {
    match c {
        Column::Name => "Süreç",
        Column::Pid => "PID",
        Column::Cpu => "CPU %",
        Column::Mem => "Bellek",
        Column::Threads => "Thread",
        Column::User => "Kullanıcı",
        Column::Description => "Açıklama",
        Column::Company => "Şirket",
        Column::Vt => "VirusTotal",
    }
}

/// Present values in `desc`/asc order; missing values always last.
fn opt<T: Ord>(a: Option<T>, b: Option<T>, desc: bool) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) if desc => b.cmp(&a),
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn lower(s: Option<String>) -> Option<String> {
    s.map(|s| s.to_lowercase())
}

fn vt_key(v: Option<VtState>) -> Option<u32> {
    match v {
        Some(VtState::Done { malicious, .. }) => Some(malicious),
        _ => None,
    }
}

/// `meta` is only consulted for Açıklama / Şirket / VirusTotal. Ties are broken by ascending pid.
pub fn comparator<'a>(col: Column, desc: bool, meta: &'a MetaFn<'a>) -> impl Fn(&ProcInfo, &ProcInfo) -> Ordering + 'a {
    move |a: &ProcInfo, b: &ProcInfo| {
        let dir = |o: Ordering| if desc { o.reverse() } else { o };
        let o = match col {
            Column::Name => dir(a.name.to_lowercase().cmp(&b.name.to_lowercase())),
            Column::Pid => dir(a.pid.cmp(&b.pid)),
            Column::Cpu => dir(a.cpu.total_cmp(&b.cpu)),
            Column::Mem => dir(a.mem.cmp(&b.mem)),
            Column::Threads => opt(a.threads, b.threads, desc),
            Column::User => dir(a.user.cmp(&b.user)),
            Column::Description => opt(lower(meta(a).0), lower(meta(b).0), desc),
            Column::Company => opt(lower(meta(a).1), lower(meta(b).1), desc),
            Column::Vt => opt(vt_key(meta(a).2), vt_key(meta(b).2), desc),
        };
        o.then(a.pid.cmp(&b.pid))
    }
}

pub enum Action {
    /// Needs confirmation: Sonlandır / Zorla sonlandır / Ağacı sonlandır.
    Kill { pid: Pid, sig: Sig, tree: bool },
    Signal { pid: Pid, start: u64, sig: Sig },
    Nice { pid: Pid, start: u64 },
    Reveal(PathBuf),
    Properties { pid: Pid, start: u64 },
    ToggleColumn(Column),
    /// Move this exe to the front of the VirusTotal queue.
    VtCheck(PathBuf),
}

/// Per-frame inputs owned by the app.
pub struct View<'a> {
    pub procs: &'a HashMap<Pid, ProcInfo>,
    pub tracker: &'a Tracker,
    pub meta: &'a MetaCache,
    pub columns: &'a [Column],
    pub query: &'a str,
    pub flat: bool,
    /// False while minimized: no metadata or icon requests.
    pub load_meta: bool,
    /// A confirmation/Öncelik dialog is open: keys must not retarget it.
    pub modal_open: bool,
    /// Present only while VirusTotal is on.
    pub vt: Option<&'a VtService>,
}

pub struct TreeView {
    pub selected: Option<(Pid, u64)>,
    /// Process the open context menu acts on; fixed at right-click (the popup itself is bound to a row index).
    menu_target: Option<(Pid, u64)>,
    collapsed: HashSet<Pid>,
    sort: Column,
    desc: bool,
    scroll_to: Option<usize>,
    /// Scroll to `selected` on the next frame (set by `reveal`).
    scroll_sel: bool,
    icons: HashMap<PathBuf, Option<TextureHandle>>,
}

impl Default for TreeView {
    fn default() -> Self {
        Self { selected: None, menu_target: None, collapsed: HashSet::new(), sort: Column::Pid, desc: false, scroll_to: None, scroll_sel: false, icons: HashMap::new() }
    }
}

fn row_colour(life: Life, p: &ProcInfo, own_uid: u32) -> Option<Color32> {
    Some(match life {
        Life::New => Color32::from_rgba_unmultiplied(0, 200, 0, 70),
        Life::Exited => Color32::from_rgba_unmultiplied(230, 0, 0, 80),
        Life::Normal if matches!(p.status, ProcStatus::Stopped) => Color32::from_rgba_unmultiplied(128, 128, 128, 90),
        Life::Normal if p.uid == own_uid => Color32::from_rgba_unmultiplied(110, 170, 255, 45),
        Life::Normal if p.uid < 500 => Color32::from_rgba_unmultiplied(255, 120, 200, 45),
        Life::Normal => return None,
    })
}

fn width(c: Column) -> egui_extras::Column {
    let w = match c {
        Column::Name => 280.0,
        Column::Description => 200.0,
        Column::Company => 150.0,
        Column::User | Column::Mem | Column::Vt => 90.0,
        _ => 60.0,
    };
    egui_extras::Column::initial(w).at_least(30.0).clip(true)
}

fn cell_text(c: Column, p: &ProcInfo, m: Option<&Meta>) -> String {
    let dash = || "—".to_string();
    match c {
        Column::Name => if p.name.is_empty() { dash() } else { p.name.clone() },
        Column::Pid => p.pid.to_string(),
        Column::Cpu => fmt::pct(p.cpu),
        Column::Mem => fmt::bytes(p.mem),
        Column::Threads => p.threads.map_or_else(dash, |t| t.to_string()),
        Column::User => if p.user.is_empty() { dash() } else { p.user.clone() },
        Column::Description => m.and_then(|m| m.description.clone()).unwrap_or_else(dash),
        Column::Company => m.and_then(|m| m.company.clone()).unwrap_or_else(dash),
        Column::Vt => dash(), // rendered by vt_cell
    }
}

/// VirusTotal cell: state text, red when any engine flags the file.
fn vt_cell(s: Option<&VtState>) -> RichText {
    match s {
        None => RichText::new("—"),
        Some(s @ VtState::Done { malicious, .. }) if *malicious > 0 => RichText::new(s.text()).color(Color32::RED),
        Some(s) => RichText::new(s.text()),
    }
}

fn menu(ui: &mut egui::Ui, p: &ProcInfo, vt_on: bool) -> Option<Action> {
    let (pid, start) = (p.pid, p.start_time);
    let mut act = None;
    if ui.button("Sonlandır").clicked() {
        act = Some(Action::Kill { pid, sig: Sig::Term, tree: false });
    }
    if ui.button("Zorla sonlandır").clicked() {
        act = Some(Action::Kill { pid, sig: Sig::Kill, tree: false });
    }
    if ui.add_enabled(super::tree_kill_allowed(pid), egui::Button::new("Ağacı sonlandır")).clicked() {
        act = Some(Action::Kill { pid, sig: Sig::Kill, tree: true });
    }
    let (label, sig) = if matches!(p.status, ProcStatus::Stopped) { ("Devam ettir", Sig::Cont) } else { ("Duraklat", Sig::Stop) };
    if ui.add_enabled(!matches!(sig, Sig::Stop) || super::pause_allowed(pid), egui::Button::new(label)).clicked() {
        act = Some(Action::Signal { pid, start, sig });
    }
    if ui.button("Öncelik…").clicked() {
        act = Some(Action::Nice { pid, start });
    }
    ui.separator();
    if ui.add_enabled(p.exe.is_some(), egui::Button::new("Finder'da göster")).clicked() {
        act = p.exe.clone().map(Action::Reveal);
    }
    if ui.button("Özellikler").clicked() {
        act = Some(Action::Properties { pid, start });
    }
    if vt_on && ui.add_enabled(p.exe.is_some(), egui::Button::new("VirusTotal'da şimdi kontrol et")).clicked() {
        act = p.exe.clone().map(Action::VtCheck);
    }
    act
}

impl TreeView {
    /// Select `(pid, start)`, unfold its ancestors and scroll to it on the next frame.
    pub fn reveal(&mut self, pid: Pid, start: u64, procs: &HashMap<Pid, ProcInfo>) {
        self.selected = Some((pid, start));
        self.scroll_sel = true;
        let mut seen = HashSet::new();
        let mut cur = procs.get(&pid).map(|p| p.ppid);
        // `seen` stops PID == PPID and longer cycles.
        while let Some(pp) = cur.filter(|pp| seen.insert(*pp)) {
            self.collapsed.remove(&pp);
            cur = procs.get(&pp).map(|p| p.ppid);
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, v: &View) -> Option<Action> {
        let Self { selected, menu_target, collapsed, sort, desc, scroll_to, scroll_sel, icons } = self;
        let meta_of = |p: &ProcInfo| -> Option<Arc<Meta>> {
            if !v.load_meta {
                return None;
            }
            p.exe.as_deref().and_then(|e| v.meta.get(e))
        };
        let vt_of = |p: &ProcInfo| Some(v.vt?.state(p.exe.as_deref()?));
        let meta_fn = |p: &ProcInfo| {
            let (d, c) = meta_of(p).map_or((None, None), |m| (m.description.clone(), m.company.clone()));
            (d, c, vt_of(p))
        };
        // shortcut: rows rebuilt every frame (frames only happen on new data/input); cache if profiling says so.
        let rows = build_rows(v.procs, &ViewOpts { collapsed, query: v.query, flat: v.flat }, &comparator(*sort, *desc, &meta_fn));
        let start_of = |pid: Pid| v.procs[&pid].start_time;
        let sel_idx = rows.iter().position(|r| Some((r.pid, start_of(r.pid))) == *selected);
        if std::mem::take(scroll_sel) {
            *scroll_to = sel_idx;
        }

        let mut act = None;
        let mut new_idx = None;
        let mut toggle = None;
        if !v.modal_open && !ui.ctx().egui_wants_keyboard_input() && !rows.is_empty() {
            let last = rows.len() - 1;
            let cur = sel_idx.unwrap_or(0);
            ui.input(|i| {
                let moved = if i.key_pressed(Key::ArrowDown) {
                    Some(sel_idx.map_or(0, |c| (c + 1).min(last)))
                } else if i.key_pressed(Key::ArrowUp) {
                    Some(cur.saturating_sub(1))
                } else if i.key_pressed(Key::PageDown) {
                    Some((cur + 20).min(last))
                } else if i.key_pressed(Key::PageUp) {
                    Some(cur.saturating_sub(20))
                } else if i.key_pressed(Key::Home) {
                    Some(0)
                } else if i.key_pressed(Key::End) {
                    Some(last)
                } else {
                    None
                };
                new_idx = moved;
                if let Some(r) = sel_idx.map(|s| &rows[s]) {
                    let folded = collapsed.contains(&r.pid);
                    if r.has_children && ((i.key_pressed(Key::ArrowLeft) && !folded) || (i.key_pressed(Key::ArrowRight) && folded)) {
                        toggle = Some(r.pid);
                    }
                    if i.key_pressed(Key::Enter) {
                        act = Some(Action::Properties { pid: r.pid, start: start_of(r.pid) });
                    }
                    if i.key_pressed(Key::Delete) || i.key_pressed(Key::Backspace) {
                        act = Some(Action::Kill { pid: r.pid, sig: Sig::Term, tree: false });
                    }
                }
            });
        }
        if let Some(i) = new_idx {
            *scroll_to = Some(i);
        }

        let own_uid = unsafe { libc::getuid() };
        let mut tb = egui_extras::TableBuilder::new(ui)
            .resizable(true)
            .sense(Sense::click())
            .auto_shrink(false)
            .cell_layout(Layout::left_to_right(Align::Center));
        for &c in v.columns {
            tb = tb.column(width(c));
        }
        if let Some(i) = scroll_to.take() {
            tb = tb.scroll_to_row(i, None);
        }
        let mut new_sort = None;
        tb.header(22.0, |mut h| {
            for &c in v.columns {
                h.col(|ui| {
                    let arrow = if c != *sort { "" } else if *desc { " ⏷" } else { " ⏶" };
                    let r = ui.add(Label::new(RichText::new(format!("{}{arrow}", title(c))).strong()).sense(Sense::click()).selectable(false));
                    if r.clicked() {
                        new_sort = Some(c);
                    }
                    r.context_menu(|ui| {
                        for c in ALL_COLUMNS {
                            let mut on = v.columns.contains(&c);
                            if ui.add_enabled(c != Column::Name, egui::Checkbox::new(&mut on, title(c))).changed() {
                                act = Some(Action::ToggleColumn(c));
                            }
                        }
                    });
                });
            }
        })
        .body(|mut body| {
            let clip = body.ui_mut().clip_rect();
            body.rows(20.0, rows.len(), |mut row| {
                let r = &rows[row.index()];
                let p = &v.procs[&r.pid];
                let is_sel = Some((p.pid, p.start_time)) == *selected || new_idx == Some(row.index());
                row.set_selected(is_sel);
                let m = meta_of(p);
                let tint = row_colour(v.tracker.life(p.pid), p, own_uid);
                for &c in v.columns {
                    row.col(|ui| {
                        // Per cell, over the row's selection/hover background; covers the gaps between cells.
                        if let Some(col) = tint {
                            let rect = ui.max_rect().expand2(ui.spacing().item_spacing / 2.0);
                            let mut pt = ui.painter().clone();
                            pt.set_clip_rect(rect.intersect(clip));
                            pt.rect_filled(rect, 0.0, col);
                        }
                        if c == Column::Vt {
                            let s = vt_of(p);
                            let r = ui.add(Label::new(vt_cell(s.as_ref())).selectable(false));
                            if let Some(VtState::Error(why)) = s {
                                r.on_hover_text(why);
                            }
                            return;
                        }
                        if c != Column::Name {
                            ui.add(Label::new(cell_text(c, p, m.as_deref())).selectable(false));
                            return;
                        }
                        ui.add_space(r.depth as f32 * 14.0);
                        if r.has_children {
                            let arrow = if collapsed.contains(&p.pid) { "⏵" } else { "⏷" };
                            if ui.add(egui::Button::new(arrow).frame(false).small()).clicked() {
                                toggle = Some(p.pid);
                            }
                        } else {
                            ui.add_space(14.0);
                        }
                        let icon = m.as_ref().and_then(|m| {
                            let exe = p.exe.as_ref()?;
                            icons
                                .entry(exe.clone())
                                .or_insert_with(|| {
                                    let px = m.icon.as_ref().filter(|b| b.len() == 32 * 32 * 4)?;
                                    let img = egui::ColorImage::from_rgba_unmultiplied([32, 32], px);
                                    Some(ui.ctx().load_texture(exe.to_string_lossy(), img, egui::TextureOptions::LINEAR))
                                })
                                .clone()
                        });
                        match icon {
                            Some(t) => {
                                ui.add(egui::Image::from_texture((t.id(), egui::vec2(16.0, 16.0))));
                            }
                            None => ui.add_space(16.0),
                        }
                        ui.add(Label::new(cell_text(c, p, None)).selectable(false));
                    });
                }
                let resp = row.response();
                if resp.clicked() || resp.secondary_clicked() {
                    *selected = Some((p.pid, p.start_time));
                }
                if resp.double_clicked() {
                    act = Some(Action::Properties { pid: p.pid, start: p.start_time });
                }
                if resp.secondary_clicked() {
                    *menu_target = Some((p.pid, p.start_time));
                }
                resp.context_menu(|ui| {
                    let target = menu_target
                        .and_then(|(pid, start)| v.procs.get(&pid).filter(|t| t.start_time == start))
                        .filter(|t| v.tracker.life(t.pid) != Life::Exited);
                    match target {
                        Some(t) => {
                            if let Some(a) = menu(ui, t, v.vt.is_some()) {
                                act = Some(a);
                            }
                        }
                        None => {
                            ui.add_enabled(false, Label::new("Süreç sonlandı"));
                        }
                    }
                });
            });
        });

        if let Some(i) = new_idx {
            *selected = Some((rows[i].pid, start_of(rows[i].pid)));
        }
        if let Some(pid) = toggle {
            if !collapsed.remove(&pid) {
                collapsed.insert(pid);
            }
        }
        if let Some(c) = new_sort {
            *desc = c == *sort && !*desc;
            *sort = c;
        }
        act
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProcStatus;

    fn p(pid: i32, cpu: f32) -> ProcInfo {
        ProcInfo {
            pid,
            ppid: 1,
            name: format!("p{pid}"),
            exe: Some(format!("/bin/p{pid}").into()),
            user: "u".into(),
            uid: 501,
            cpu,
            mem: 0,
            threads: None,
            status: ProcStatus::Running,
            start_time: 0,
            disk_read: 0,
            disk_write: 0,
        }
    }
    fn no_meta(_: &ProcInfo) -> (Option<String>, Option<String>, Option<VtState>) {
        (None, None, None)
    }
    fn sorted(mut v: Vec<ProcInfo>, col: Column, desc: bool, meta: &MetaFn) -> Vec<i32> {
        let c = comparator(col, desc, meta);
        v.sort_by(|a, b| c(a, b));
        v.iter().map(|x| x.pid).collect()
    }

    #[test]
    fn reveal_unfolds_ancestors_and_survives_cycles() {
        let mut procs: HashMap<Pid, ProcInfo> = HashMap::new();
        for (pid, ppid) in [(1, 1), (10, 1), (11, 10), (12, 11), (20, 21), (21, 20)] {
            procs.insert(pid, ProcInfo { ppid, ..p(pid, 0.0) });
        }
        let mut t = TreeView::default();
        t.collapsed.extend([1, 10, 11, 12, 20]);
        t.reveal(12, 0, &procs);
        assert_eq!(t.selected, Some((12, 0)));
        assert!(t.scroll_sel);
        assert_eq!(t.collapsed, HashSet::from([12, 20]));
        t.reveal(20, 0, &procs); // 20 <-> 21 cycle must terminate
        assert!(!t.collapsed.contains(&20));
    }

    #[test]
    fn vt_cell_red_only_when_flagged() {
        let flagged = VtState::Done { malicious: 2, total: 70 };
        assert_eq!(vt_cell(Some(&flagged)), RichText::new("2/70").color(Color32::RED));
        assert_eq!(vt_cell(Some(&VtState::Done { malicious: 0, total: 70 })), RichText::new("0/70"));
        assert_eq!(vt_cell(Some(&VtState::Pending)), RichText::new("bekliyor"));
        assert_eq!(vt_cell(None), RichText::new("—"));
    }

    #[test]
    fn sort_by_cpu_desc() {
        let v = vec![p(1, 5.0), p(2, 90.0), p(3, 20.0)];
        assert_eq!(sorted(v, Column::Cpu, true, &no_meta), [2, 3, 1]);
    }

    #[test]
    fn sort_by_company_puts_none_last() {
        let meta = |x: &ProcInfo| {
            let c = match x.pid {
                1 => Some("Zeta".to_string()),
                3 => Some("Apple".to_string()),
                _ => None,
            };
            (None, c, None)
        };
        let v = || vec![p(2, 0.0), p(1, 0.0), p(4, 0.0), p(3, 0.0)];
        assert_eq!(sorted(v(), Column::Company, false, &meta), [3, 1, 2, 4]);
        assert_eq!(sorted(v(), Column::Company, true, &meta), [1, 3, 2, 4]);
    }

    #[test]
    fn ties_broken_by_pid() {
        let v = vec![p(9, 1.0), p(3, 1.0), p(5, 1.0)];
        assert_eq!(sorted(v.clone(), Column::Cpu, false, &no_meta), [3, 5, 9]);
        assert_eq!(sorted(v, Column::Cpu, true, &no_meta), [3, 5, 9]);
    }
}
