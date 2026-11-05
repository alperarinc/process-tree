//! Top bar: mini system graphs, filter box, tree/list toggle, mode buttons.
use crate::fmt;
use crate::lifecycle::Ring;
use crate::model::SystemStats;
use eframe::egui::{self, Color32, Sense, Stroke};

const SAMPLES: usize = 120;

pub struct History {
    cpu: Ring<f32>,
    mem: Ring<f32>,
    disk: Ring<f32>,
    net: Ring<f32>,
    last: Option<SystemStats>,
}

impl Default for History {
    fn default() -> Self {
        Self { cpu: Ring::new(SAMPLES), mem: Ring::new(SAMPLES), disk: Ring::new(SAMPLES), net: Ring::new(SAMPLES), last: None }
    }
}

impl History {
    pub fn push(&mut self, s: &SystemStats) {
        self.cpu.push(s.cpu);
        self.mem.push(if s.mem_total == 0 { 0.0 } else { s.mem_used as f32 * 100.0 / s.mem_total as f32 });
        self.disk.push((s.disk_read_bps + s.disk_write_bps) as f32);
        self.net.push((s.net_rx_bps + s.net_tx_bps) as f32);
        self.last = Some(s.clone());
    }
}

/// `max` None = scale to the largest sample.
fn graph(ui: &mut egui::Ui, label: String, ring: &Ring<f32>, max: Option<f32>, colour: Color32) {
    ui.vertical(|ui| {
        ui.small(label);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(110.0, 26.0), Sense::hover());
        let p = ui.painter();
        p.rect_filled(rect, 2.0, ui.visuals().extreme_bg_color);
        let top = max.unwrap_or_else(|| ring.iter().copied().fold(1.0, f32::max));
        let dx = rect.width() / (SAMPLES - 1) as f32;
        let x0 = rect.right() - dx * (ring.len().max(1) - 1) as f32;
        let pts: Vec<_> = ring
            .iter()
            .enumerate()
            .map(|(i, v)| egui::pos2(x0 + dx * i as f32, rect.bottom() - (v / top).clamp(0.0, 1.0) * rect.height()))
            .collect();
        p.add(egui::Shape::line(pts, Stroke::new(1.0, colour)));
    });
}

#[derive(Default)]
pub struct Out {
    /// Tree/list mode changed.
    pub mode_changed: bool,
    pub admin: bool,
    /// Drag started on Nişangâh: enter picking mode.
    pub pick: bool,
    pub settings: bool,
}

/// `admin`: helper connected; `admin_pending`: password prompt / connect in progress.
pub fn show(ui: &mut egui::Ui, h: &History, query: &mut String, flat: &mut bool, admin: bool, admin_pending: bool) -> Out {
    let was = *flat;
    let mut out = Out::default();
    ui.horizontal(|ui| {
        let s = h.last.as_ref();
        graph(ui, format!("CPU {}%", fmt::pct(s.map_or(0.0, |s| s.cpu))), &h.cpu, Some(100.0), Color32::from_rgb(80, 200, 80));
        graph(ui, format!("Bellek {}", fmt::bytes(s.map_or(0, |s| s.mem_used))), &h.mem, Some(100.0), Color32::from_rgb(230, 180, 60));
        graph(ui, format!("Disk {}", fmt::rate(s.map_or(0, |s| s.disk_read_bps + s.disk_write_bps))), &h.disk, None, Color32::from_rgb(90, 150, 240));
        graph(ui, format!("Ağ {}", fmt::rate(s.map_or(0, |s| s.net_rx_bps + s.net_tx_bps))), &h.net, None, Color32::from_rgb(200, 100, 220));
        ui.separator();
        ui.add(egui::TextEdit::singleline(query).hint_text("Ara: ad, PID veya yol").desired_width(220.0));
        ui.selectable_value(flat, false, "Ağaç");
        ui.label("/");
        ui.selectable_value(flat, true, "Liste");
        ui.separator();
        out.admin = ui.add_enabled(!admin && !admin_pending, egui::Button::new("Yönetici modu")).clicked();
        if admin {
            ui.label(egui::RichText::new("Yönetici").strong().color(Color32::from_rgb(230, 120, 40)));
        }
        out.pick = ui
            .add(egui::Button::new("Nişangâh").sense(Sense::click_and_drag()))
            .on_hover_text("Basılı tutup bir pencerenin üzerine sürükleyin")
            .drag_started();
        out.settings = ui.button("Ayarlar").clicked();
    });
    out.mode_changed = was != *flat;
    out
}
