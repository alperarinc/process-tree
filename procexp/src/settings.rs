//! Persistent user settings (`settings.json`, mode 0600 because it holds the VirusTotal key).
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Column {
    Name,
    Pid,
    Cpu,
    Mem,
    Threads,
    User,
    Description,
    Company,
    Vt,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub interval_ms: u64,
    pub columns: Vec<Column>,
    pub flat: bool,
    pub vt_enabled: bool,
    pub vt_api_key: String,
}

impl Default for Settings {
    fn default() -> Self {
        use Column::*;
        Self {
            interval_ms: 1000,
            columns: vec![Name, Pid, Cpu, Mem, Threads, User, Description, Company],
            flat: false,
            vt_enabled: false,
            vt_api_key: String::new(),
        }
    }
}

// Hand-written so `{:?}` can never leak the API key.
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("interval_ms", &self.interval_ms)
            .field("columns", &self.columns)
            .field("flat", &self.flat)
            .field("vt_enabled", &self.vt_enabled)
            .field("vt_api_key", &"<redacted>")
            .finish()
    }
}

/// Write via `<path>.tmp` (created 0600) + rename, so a crash never leaves a truncated file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    // `mode` only applies on creation; tighten a leftover tmp too.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// `$HOME/Library/Application Support/ProcessTree`, created on demand.
pub fn app_support_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    let dir = home.join("Library/Application Support/ProcessTree");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn load(path: &Path) -> Settings {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

impl Settings {
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        write_atomic(path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip_and_0600() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        let s = Settings { interval_ms: 2500, flat: true, vt_enabled: true, vt_api_key: "k".into(), columns: vec![Column::Name, Column::Vt] };
        s.save(&p).unwrap();
        assert_eq!(load(&p), s);
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn debug_redacts_key() {
        let s = Settings { vt_api_key: "sekrit-key".into(), ..Default::default() };
        assert!(!format!("{s:?}").contains("sekrit-key"));
    }

    #[test]
    fn save_over_leftover_tmp_keeps_real_file_valid() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        let s = Settings { interval_ms: 3000, ..Default::default() };
        s.save(&p).unwrap();
        std::fs::write(d.path().join("settings.json.tmp"), "garbage").unwrap();
        assert_eq!(load(&p), s);
        s.save(&p).unwrap();
        assert_eq!(load(&p), s);
    }

    #[test]
    fn corrupt_settings_fall_back_to_default() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        assert_eq!(load(&p), Settings::default());
        std::fs::write(&p, "{not json").unwrap();
        assert_eq!(load(&p), Settings::default());
    }
}
