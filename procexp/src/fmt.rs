/// Locale-independent: always `.` as decimal separator.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn pct(p: f32) -> String {
    format!("{p:.1}")
}

pub fn rate(bps: u64) -> String {
    format!("{}/s", bytes(bps))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn locale_free() {
        assert_eq!(pct(3.66), "3.7");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(0), "0 B");
        assert_eq!(rate(2 * 1024 * 1024), "2.0 MB/s");
    }
}
