//! Code-signing info, company, bundle description and icons for executables.
use core_foundation::base::{CFType, TCFType};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use core_foundation_sys::array::{CFArrayGetCount, CFArrayGetValueAtIndex};
use core_foundation_sys::base::{CFRelease, CFTypeRef, OSStatus};
use core_foundation_sys::dictionary::{CFDictionaryGetValue, CFDictionaryRef};
use core_foundation_sys::string::CFStringRef;
use objc2::rc::autoreleasepool;
use objc2::AnyThread;
use objc2_app_kit::{
    NSBitmapImageRep, NSCalibratedRGBColorSpace, NSCompositingOperation, NSGraphicsContext,
    NSWorkspace,
};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
use security_framework_sys::certificate::SecCertificateCopySubjectSummary;
use security_framework_sys::code_signing::*;
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::ptr;

#[derive(Debug, Clone, PartialEq)]
pub struct Signing {
    pub valid: bool,
    pub authority: Option<String>,
    pub team_id: Option<String>,
    pub company: Option<String>,
    pub platform: bool,
}

extern "C" {
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        info: *mut CFDictionaryRef,
    ) -> OSStatus;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoPlatformIdentifier: CFStringRef;
    static kSecCodeInfoCertificates: CFStringRef;
}
const SIGNING_INFORMATION: u32 = 1 << 1; // kSecCSSigningInformation

/// Owns a +1 CF object and releases it on drop.
struct Owned(CFTypeRef);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) }
        }
    }
}

pub fn company_from_subject(subject: &str, platform: bool) -> Option<String> {
    if platform || subject == "Software Signing" {
        return Some("Apple Inc.".into());
    }
    let (_, name) = subject.split_once(": ")?;
    let name = match name.rsplit_once(" (") {
        Some((n, rest)) if rest.ends_with(')') => n,
        _ => name,
    };
    Some(name.to_string())
}

pub fn signing_info(path: &Path) -> Option<Signing> {
    let url = CFURL::from_path(path, false)?;
    let mut code: SecStaticCodeRef = ptr::null_mut();
    if unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef(), 0, &mut code) } != 0 {
        return None;
    }
    let _code = Owned(code as CFTypeRef);
    // Resources are skipped: hashing every file of a big .app per process is too costly.
    let valid = unsafe {
        SecStaticCodeCheckValidity(code, kSecCSDoNotValidateResources, ptr::null_mut())
    } == 0;

    let mut dict: CFDictionaryRef = ptr::null();
    if unsafe { SecCodeCopySigningInformation(code, SIGNING_INFORMATION, &mut dict) } != 0 {
        return Some(Signing { valid, authority: None, team_id: None, company: None, platform: false });
    }
    let _dict = Owned(dict as CFTypeRef);
    let get = |k: CFStringRef| unsafe { CFDictionaryGetValue(dict, k as *const c_void) };

    let team_id = unsafe {
        let v = get(kSecCodeInfoTeamIdentifier);
        (!v.is_null()).then(|| CFString::wrap_under_get_rule(v as CFStringRef).to_string())
    };
    let platform = unsafe {
        let v = get(kSecCodeInfoPlatformIdentifier);
        !v.is_null()
            && CFType::wrap_under_get_rule(v as CFTypeRef)
                .downcast::<CFNumber>()
                .and_then(|n| n.to_i32())
                .is_some_and(|n| n != 0)
    };
    let authority = unsafe {
        let certs = get(kSecCodeInfoCertificates);
        if certs.is_null() || CFArrayGetCount(certs as _) == 0 {
            None
        } else {
            let leaf = CFArrayGetValueAtIndex(certs as _, 0);
            let s = SecCertificateCopySubjectSummary(leaf as _);
            (!s.is_null()).then(|| CFString::wrap_under_create_rule(s).to_string())
        }
    };
    let company = authority
        .as_deref()
        .and_then(|a| company_from_subject(a, platform))
        .or_else(|| platform.then(|| "Apple Inc.".to_string()));
    Some(Signing { valid, authority, team_id, company, platform })
}

pub fn bundle_root(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .skip(1)
        .find(|a| a.extension().is_some_and(|e| e == "app") && a.join("Contents").is_dir())
        .map(Path::to_path_buf)
}

pub fn bundle_description(bundle: &Path) -> Option<String> {
    let v = plist::Value::from_file(bundle.join("Contents/Info.plist")).ok()?;
    let d = v.as_dictionary()?;
    ["CFBundleDisplayName", "CFBundleName"]
        .iter()
        .find_map(|k| d.get(k)?.as_string().filter(|s| !s.is_empty()))
        .map(str::to_string)
}

/// Straight (non-premultiplied) RGBA, `size`×`size`. Offscreen bitmap only, safe off the main thread.
pub fn icon_rgba(path: &Path, size: u32) -> Option<Vec<u8>> {
    let target = bundle_root(path).unwrap_or_else(|| path.to_path_buf());
    let n = size as isize;
    autoreleasepool(|_| unsafe {
        let ws = NSWorkspace::sharedWorkspace();
        let img = ws.iconForFile(&NSString::from_str(target.to_str()?));
        let rep = NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel(
            NSBitmapImageRep::alloc(), ptr::null_mut(), n, n, 8, 4, true, false,
            NSCalibratedRGBColorSpace, n * 4, 32,
        )?;
        let ctx = NSGraphicsContext::graphicsContextWithBitmapImageRep(&rep)?;
        NSGraphicsContext::saveGraphicsState_class();
        NSGraphicsContext::setCurrentContext(Some(&ctx));
        let full = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(size as f64, size as f64));
        img.drawInRect_fromRect_operation_fraction(
            full,
            NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(0.0, 0.0)), // zero rect = whole image
            NSCompositingOperation::SourceOver,
            1.0,
        );
        NSGraphicsContext::restoreGraphicsState_class();
        let data = rep.bitmapData();
        if data.is_null() {
            return None;
        }
        let mut out = std::slice::from_raw_parts(data, (size * size * 4) as usize).to_vec();
        for px in out.chunks_exact_mut(4) {
            let a = px[3] as u32;
            if a != 0 && a != 255 {
                for c in &mut px[..3] {
                    *c = ((*c as u32 * 255 + a / 2) / a).min(255) as u8;
                }
            }
        }
        Some(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn company_parsing() {
        assert_eq!(company_from_subject("Developer ID Application: Google LLC (EQHXZ8M8AV)", false).as_deref(), Some("Google LLC"));
        assert_eq!(company_from_subject("Apple Development: X (Y)", false).as_deref(), Some("X"));
        assert_eq!(company_from_subject("Software Signing", false).as_deref(), Some("Apple Inc."));
        assert_eq!(company_from_subject("whatever", true).as_deref(), Some("Apple Inc."));
        assert_eq!(company_from_subject("whatever", false), None);
    }

    #[test]
    fn bundle_root_finds_app() {
        assert_eq!(
            bundle_root(Path::new("/Applications/Safari.app/Contents/MacOS/Safari")).as_deref(),
            Some(Path::new("/Applications/Safari.app"))
        );
        assert_eq!(bundle_root(Path::new("/bin/ls")), None);
    }

    #[test]
    fn calculator_description() {
        assert!(bundle_description(Path::new("/System/Applications/Calculator.app")).is_some());
    }

    #[test]
    fn ls_is_apple_platform_signed() {
        let s = signing_info(Path::new("/bin/ls")).expect("signing info");
        assert!(s.valid);
        assert_eq!(s.company.as_deref(), Some("Apple Inc."));
    }

    #[test]
    fn unsigned_file_is_not_valid() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("script.sh");
        std::fs::write(&p, "#!/bin/sh\necho hi\n").unwrap();
        assert!(signing_info(&p).is_none_or(|s| !s.valid));
    }

    #[test]
    fn icon_has_right_size() {
        let v = icon_rgba(Path::new("/System/Applications/Calculator.app"), 32).unwrap();
        assert_eq!(v.len(), 32 * 32 * 4);
        assert!(v.chunks_exact(4).any(|p| p[3] != 0), "icon is fully transparent");
    }
}
