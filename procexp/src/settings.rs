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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        // `mode` only applies on creation; tighten a pre-existing file too.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(&json)
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
    fn corrupt_settings_fall_back_to_default() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        assert_eq!(load(&p), Settings::default());
        std::fs::write(&p, "{not json").unwrap();
        assert_eq!(load(&p), Settings::default());
    }
}
