//! Window picker primitives: CoreGraphics window list, global mouse, pure hit-test.
use crate::model::Pid;
use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::array::CFArrayRef;
use core_foundation_sys::base::{CFRelease, CFTypeRef};
use std::ffi::c_void;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WinInfo {
    pub owner_pid: Pid,
    pub layer: i32,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CGPoint {
    x: f64,
    y: f64,
}

const ON_SCREEN_ONLY: u32 = 1;
const EXCLUDE_DESKTOP: u32 = 1 << 4;
const COMBINED_SESSION_STATE: i32 = 0;
const BUTTON_LEFT: u32 = 0;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGWindowListCopyWindowInfo(option: u32, relative_to: u32) -> CFArrayRef;
    fn CGEventCreate(source: *const c_void) -> CFTypeRef;
    fn CGEventGetLocation(event: CFTypeRef) -> CGPoint;
    fn CGEventSourceButtonState(state: i32, button: u32) -> bool;
}

/// First (front-most) normal-layer window under the point, not owned by `exclude`.
pub fn pick_window(wins: &[WinInfo], x: f64, y: f64, exclude: Pid) -> Option<Pid> {
    wins.iter()
        .find(|w| {
            w.layer == 0
                && w.owner_pid != exclude
                && x >= w.x
                && x < w.x + w.w
                && y >= w.y
                && y < w.y + w.h
        })
        .map(|w| w.owner_pid)
}

fn num(d: &CFDictionary<CFString, CFType>, key: &str) -> Option<f64> {
    d.find(CFString::new(key))?.downcast::<CFNumber>()?.to_f64()
}

pub fn on_screen_windows() -> Vec<WinInfo> {
    // SAFETY: Copy rule, so the array is ours; wrap_under_create_rule releases it exactly once.
    let raw = unsafe { CGWindowListCopyWindowInfo(ON_SCREEN_ONLY | EXCLUDE_DESKTOP, 0) };
    if raw.is_null() {
        return Vec::new();
    }
    let arr: CFArray<CFDictionary<CFString, CFType>> = unsafe { CFArray::wrap_under_create_rule(raw) };
    arr.iter()
        .filter_map(|d| {
            let b = d.find(CFString::new("kCGWindowBounds"))?.downcast::<CFDictionary>()?;
            let b: CFDictionary<CFString, CFType> =
                unsafe { CFDictionary::wrap_under_get_rule(b.as_concrete_TypeRef()) };
            Some(WinInfo {
                owner_pid: num(&d, "kCGWindowOwnerPID")? as Pid,
                layer: num(&d, "kCGWindowLayer")? as i32,
                x: num(&b, "X")?,
                y: num(&b, "Y")?,
                w: num(&b, "Width")?,
                h: num(&b, "Height")?,
            })
        })
        .collect()
}

pub fn global_mouse() -> (f64, f64) {
    // SAFETY: CGEventCreate follows the Create rule; released once below.
    unsafe {
        let ev = CGEventCreate(std::ptr::null());
        if ev.is_null() {
            return (0.0, 0.0);
        }
        let p = CGEventGetLocation(ev);
        CFRelease(ev);
        (p.x, p.y)
    }
}

pub fn left_mouse_down() -> bool {
    unsafe { CGEventSourceButtonState(COMBINED_SESSION_STATE, BUTTON_LEFT) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(pid: Pid, layer: i32, x: f64, y: f64, w: f64, h: f64) -> WinInfo {
        WinInfo { owner_pid: pid, layer, x, y, w, h }
    }

    #[test]
    fn picks_frontmost_containing() {
        let ws = [win(1, 0, 0.0, 0.0, 100.0, 100.0), win(2, 0, 50.0, 50.0, 100.0, 100.0)];
        assert_eq!(pick_window(&ws, 60.0, 60.0, 99), Some(1));
        assert_eq!(pick_window(&ws, 120.0, 120.0, 99), Some(2));
    }

    #[test]
    fn skips_menu_layer_and_self() {
        let ws = [
            win(1, 25, 0.0, 0.0, 100.0, 100.0),
            win(9, 0, 0.0, 0.0, 100.0, 100.0),
            win(3, 0, 0.0, 0.0, 100.0, 100.0),
        ];
        assert_eq!(pick_window(&ws, 10.0, 10.0, 9), Some(3));
    }

    #[test]
    fn miss_returns_none() {
        let ws = [win(1, 0, 0.0, 0.0, 10.0, 10.0)];
        assert_eq!(pick_window(&ws, 10.0, 10.0, 99), None);
        assert_eq!(pick_window(&[], 0.0, 0.0, 99), None);
    }

    #[test]
    fn on_screen_windows_runs() {
        let _ = on_screen_windows();
        let _ = global_mouse();
        let _ = left_mouse_down();
    }
}
