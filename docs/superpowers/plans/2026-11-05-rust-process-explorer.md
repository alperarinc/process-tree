# Rust Süreç Gezgini Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A native macOS process explorer in Rust (egui) with a process tree, per-process detail tabs, properties window, system graphs, actions, a crosshair window picker, a temporary root helper and automatic VirusTotal checks.

**Architecture:** Everything that reads OS data goes through a `Backend` trait. `LocalBackend` runs in the GUI process; `HelperClient` talks to the same binary started as root with `--helper`, over a Unix socket. A sampler thread pulls a `Snapshot` from the backend every interval and hands it to the egui app through a channel. Metadata (signature, description, icon) and VirusTotal run on their own background-QoS worker threads with caches. Pure logic (tree, lifecycle, formatting, parsing, picking) is separated from FFI so it can be unit-tested.

**Tech Stack:** Rust stable (1.92), eframe/egui, sysinfo, libc, libproc crate (where it covers; raw FFI otherwise), core-foundation + Security.framework FFI, core-graphics, objc2 / objc2-app-kit (icons), plist, sha2, ureq, serde/serde_json.

**Spec:** `docs/superpowers/specs/2026-11-05-rust-process-explorer-design.md`

## Global Constraints

- macOS only (Apple Silicon, Darwin 25). No Windows/Linux code paths.
- Project lives at `taskmanager/procexp/`; `ptree.py` stays untouched.
- UI copy is Turkish (exact strings below where the plan fixes them).
- CPU % is per-core scale: 100 = one full core (column and budget).
- CPU budget for the app itself with ~600 processes: **< 2 %** in background/minimized, **< 5 %** visible in front and idle.
- Number formatting/parsing must not depend on locale (`ptree.py` crashed on `3,7` under `tr_TR`).
- Every destructive action (Sonlandır, Zorla sonlandır, Ağacı sonlandır) asks for confirmation.
- No network traffic unless the user enabled VirusTotal; only SHA-256 hashes are ever sent, never file contents.
- Unreadable details show `Erişim yok — Yönetici modunu açın`, never an empty list.
- The GUI never runs as root; root work happens only in the `--helper` process, which installs nothing and exits when the GUI disconnects.
- Not a git repository: "Checkpoint" steps run the full test suite instead of committing (initialise git first if the user asks for commits).

## Review Focus

1. **PID reuse between display and action** — the user picks a row, the process exits and its PID is reused; Sonlandır must not hit the new process. Signals carry the expected start time and refuse on mismatch (Task 5 test `signal_refuses_mismatched_start_time`).
2. **Root helper disappears** (killed, crash, socket closed) — app must fall back to normal mode within one interval, not hang or panic (Task 6 test `client_reports_disconnected_after_server_exit`; Task 12 fallback step).
3. **Odd processes**: kernel_task / zombies with no exe, PID == PPID, PPID not in snapshot, non-UTF-8 or very long names — tree must place them at root level, never loop, never panic; metadata/VT skip them (Task 1 tests `orphans_and_self_parent_are_roots`, `no_exe_is_fine`).
4. **VirusTotal failure modes**: 429, 401/403 bad key, offline — items stay queued, no busy retry, column shows `hata` with reason (Task 9 tests `rate_limited_pauses_and_keeps_item`, `bad_key_stops_queue`, `offline_retries_later`).
5. **Selected process exits while detail tabs/properties are open** — tabs show `Süreç sonlandı`, not stale data or an error dialog (Task 4 test `details_of_exited_process_is_no_such_process`; Task 11 UI step).

---

## File Structure

```
procexp/
  Cargo.toml
  bundle.sh                    # build .app, ad-hoc sign, install to ~/Applications
  src/
    main.rs                    # arg parse: normal GUI vs `--helper <dir>`
    model.rs                   # Pid, ProcInfo, ProcStatus, SystemStats, Snapshot, FdEntry, ThreadEntry, ProcExtra, DetailError, Sig
    fmt.rs                     # locale-free formatting
    tree.rs                    # build_rows, descendants_postorder
    lifecycle.rs               # Tracker (new / exited highlighting), Ring<T> history
    darwin/mod.rs
    darwin/libproc.rs          # thread_count, open_fds, threads, mapped_files, proc_extra, start_time, map_errno
    darwin/meta.rs             # signing_info, company_from_subject, bundle_root, bundle_description, icon_rgba
    darwin/windows.rs          # WinInfo, pick_window, on_screen_windows, global_mouse, left_mouse_down
    sampler.rs                 # LocalSampler (sysinfo) -> Snapshot
    actions.rs                 # send_signal, renice, reveal_in_finder
    backend.rs                 # Backend trait, LocalBackend
    helper.rs                  # protocol, run_server, HelperClient, prepare_dir, launch
    metacache.rs               # MetaCache background worker
    vt.rs                      # VirusTotal: VtState, parse_response, RateLimiter, VtService
    settings.rs                # Settings, Column, load/save, app_support_dir
    ui/mod.rs                  # App (eframe::App), sampler thread wiring
    ui/toolbar.rs              # graphs, filter box, Yönetici modu, Nişangâh, settings
    ui/tree_view.rs            # table, columns, sort, colors, context menu, confirmations
    ui/details.rs              # bottom tabs
    ui/properties.rs           # properties window
  tests/darwin.rs              # integration tests against own/child processes
```

---

### Task 1: Scaffold, model, formatting, tree

**Files:**
- Create: `procexp/Cargo.toml`, `procexp/src/main.rs` (stub `fn main() {}` for now), `src/model.rs`, `src/fmt.rs`, `src/tree.rs`

**Interfaces:**
- Produces (`model.rs`, all `#[derive(Clone, Debug, Serialize, Deserialize)]`):
  - `pub type Pid = i32;`
  - `pub enum ProcStatus { Running, Sleeping, Stopped, Zombie, Other }`
  - `pub struct ProcInfo { pub pid: Pid, pub ppid: Pid, pub name: String, pub exe: Option<PathBuf>, pub user: String, pub uid: u32, pub cpu: f32, pub mem: u64, pub threads: Option<u32>, pub status: ProcStatus, pub start_time: u64, pub disk_read: u64, pub disk_write: u64 }` (cpu per-core %, mem bytes RSS, start_time unix secs, disk_* bytes since previous sample)
  - `pub struct SystemStats { pub cpu: f32, pub mem_used: u64, pub mem_total: u64, pub disk_read_bps: u64, pub disk_write_bps: u64, pub net_rx_bps: u64, pub net_tx_bps: u64 }` (cpu = whole machine 0–100)
  - `pub struct Snapshot { pub procs: HashMap<Pid, ProcInfo>, pub system: SystemStats, pub taken_at_ms: u64 }`
  - `pub enum Proto { Tcp4, Tcp6, Udp4, Udp6, Unix, Other }`
  - `pub enum FdEntry { File { fd: i32, path: String }, Socket { fd: i32, proto: Proto, local: String, remote: String, state: String }, Pipe { fd: i32 }, Other { fd: i32, kind: String } }`
  - `pub struct ThreadEntry { pub id: u64, pub name: String, pub cpu: f32, pub state: String }`
  - `pub struct ProcExtra { pub args: Vec<String>, pub env: Vec<(String, String)>, pub cwd: Option<String> }`
  - `pub enum DetailError { AccessDenied, NoSuchProcess, Disconnected, Other(String) }` + `impl Display` with Turkish text: AccessDenied → `Erişim yok — Yönetici modunu açın`, NoSuchProcess → `Süreç sonlandı`, Disconnected → `Yönetici bağlantısı koptu`.
  - `pub enum Sig { Term, Kill, Stop, Cont }`
- Produces (`fmt.rs`): `pub fn bytes(n: u64) -> String` (1024 base, one decimal, units `B KB MB GB TB`), `pub fn pct(p: f32) -> String` (one decimal), `pub fn rate(bps: u64) -> String` (`bytes(n) + "/s"`).
- Produces (`tree.rs`):
  - `pub struct Row { pub pid: Pid, pub depth: u16, pub has_children: bool }`
  - `pub struct ViewOpts<'a> { pub collapsed: &'a HashSet<Pid>, pub query: &'a str, pub flat: bool }`
  - `pub fn build_rows(procs: &HashMap<Pid, ProcInfo>, opts: &ViewOpts, cmp: &dyn Fn(&ProcInfo, &ProcInfo) -> Ordering) -> Vec<Row>`
  - `pub fn parent_of(p: &ProcInfo, procs: &HashMap<Pid, ProcInfo>) -> Option<Pid>` (None if ppid missing or == pid)
  - `pub fn descendants_postorder(procs: &HashMap<Pid, ProcInfo>, root: Pid) -> Vec<Pid>` (children before parents, root last)

Semantics copied from `ptree.py`: query (case-insensitive) matches name substring, exe path substring, or exact PID; matches keep all ancestors. Siblings are ordered by `cmp`. `flat == true`: every (filtered) process at depth 0 sorted by `cmp`, collapse ignored. Use an explicit stack, not recursion, and a visited set so a ppid cycle cannot loop.

- [ ] **Step 1: Write failing tests** in `tree.rs` / `fmt.rs` (helper `p(pid, ppid, name)` builds a ProcInfo):

```rust
// tree.rs — fixture: 0 kernel_task(ppid 0), 1 launchd(0), 10 zsh(1), 11 vim(10), 20 Finder(1)
#[test] fn tree_order_by_pid() { assert_eq!(pids(build_rows(&f, &opts(), &by_pid)), [0,1,10,11,20]); assert_eq!(depths(..), [0,1,2,3,2]); }
#[test] fn collapse_hides_children() { /* collapsed {10} */ assert_eq!(pids(..), [0,1,10,20]); }
#[test] fn filter_keeps_ancestors() { /* "VIM" */ assert_eq!(pids(..), [0,1,10,11]); /* "20" */ assert_eq!(pids(..), [0,1,20]); }
#[test] fn siblings_follow_comparator() { /* cpu desc, Finder cpu 50 > zsh 1 */ assert_eq!(pids(..), [0,1,20,10,11]); }
#[test] fn flat_mode_sorts_everything() { /* by pid desc */ assert_eq!(pids(..), [20,11,10,1,0]); assert!(depths all 0); }
#[test] fn orphans_and_self_parent_are_roots() { /* add 50 ppid 999, 60 ppid 60, cycle 70<->71 */ every pid appears exactly once; 50 and 60 depth 0 }
#[test] fn no_exe_is_fine() { /* exe None, name "" */ build_rows does not panic and includes it }
#[test] fn descendants_children_first() { assert_eq!(descendants_postorder(&f, 1), [11,10,20,1]); }
// fmt.rs
#[test] fn locale_free() { assert_eq!(pct(3.66), "3.7"); assert_eq!(bytes(1536), "1.5 KB"); assert_eq!(bytes(0), "0 B"); assert_eq!(rate(2*1024*1024), "2.0 MB/s"); }
```

- [ ] **Step 2:** `cd procexp && cargo test` → FAIL (functions missing).
- [ ] **Step 3:** Implement the interfaces above.
- [ ] **Step 4:** `cargo test` → all pass.
- [ ] **Step 5: Checkpoint** — `cargo test && cargo clippy -- -D warnings` clean.

---

### Task 2: Lifecycle tracker and history ring

**Files:** Create `src/lifecycle.rs`

**Interfaces:**
- Consumes: `Snapshot`, `ProcInfo`, `Pid`.
- Produces:
  - `pub enum Life { New, Normal, Exited }`
  - `pub struct Tracker` — `pub fn new(highlight: Duration) -> Self`, `pub fn update(&mut self, snap: &Snapshot, now: Instant)`, `pub fn life(&self, pid: Pid) -> Life`, `pub fn ghosts(&self) -> Vec<ProcInfo>` (exited processes still inside the highlight window).
  - `pub struct Ring<T> { .. }` — `pub fn new(cap: usize)`, `pub fn push(&mut self, v: T)`, `pub fn iter(&self) -> impl Iterator<Item=&T>` (oldest first), `pub fn len(&self)`.

Identity is `(pid, start_time)`: a reused PID with a new start time counts as exited + new. The very first `update` marks everything `Normal`. Highlight duration used by the app: 3 s.

- [ ] **Step 1: Failing tests:** `first_update_is_normal`, `new_process_is_new_then_normal_after_highlight`, `exited_process_is_ghost_then_dropped`, `pid_reuse_is_exit_plus_new` (same pid, different start_time → old one in `ghosts()`, `life(pid) == New`), `ring_drops_oldest` (cap 3, push 1..=5 → `[3,4,5]`).
- [ ] **Step 2:** `cargo test lifecycle` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test lifecycle` → PASS.
- [ ] **Step 5: Checkpoint** — full `cargo test`.

---

### Task 3: libproc readers

**Files:** Create `src/darwin/mod.rs`, `src/darwin/libproc.rs`, `tests/darwin.rs`

**Interfaces:**
- Consumes: model types.
- Produces (all `pub fn`, `pid: Pid`):
  - `map_errno(e: i32) -> DetailError` (EPERM/EACCES → AccessDenied, ESRCH → NoSuchProcess, else Other(strerror))
  - `start_time(pid) -> Result<u64, DetailError>` (PROC_PIDTBSDINFO `pbi_start_tvsec`)
  - `thread_count(pid) -> Result<u32, DetailError>` (PROC_PIDTASKINFO `pti_threadnum`)
  - `open_fds(pid) -> Result<Vec<FdEntry>, DetailError>` (PROC_PIDLISTFDS + proc_pidfdinfo: VNODE → File path; SOCKET → Socket with addresses as `ip:port`, TCP state name e.g. `ESTABLISHED`, `LISTEN`; unix sockets path in `local`; PIPE → Pipe)
  - `threads(pid) -> Result<Vec<ThreadEntry>, DetailError>` (PROC_PIDLISTTHREADS + PROC_PIDTHREADINFO; cpu = `pth_cpu_usage / 10.0` since TH_USAGE_SCALE = 1000 → percent; state from `pth_run_state`)
  - `mapped_files(pid) -> Result<Vec<String>, DetailError>` (walk regions with PROC_PIDREGIONPATHINFO, collect unique paths, sorted; dyld shared cache shows as its cache file — spec accepts this)
  - `proc_extra(pid) -> Result<ProcExtra, DetailError>` (args + env from sysctl `KERN_PROCARGS2`; cwd from PROC_PIDVNODEPATHINFO)

Use the `libproc` crate where it exposes these; otherwise raw `libc`/extern FFI. libproc functions return 0/-1 and set errno — always route through `map_errno`.

- [ ] **Step 1: Failing integration tests** in `tests/darwin.rs`:

```rust
#[test] fn own_thread_count_grows() { let n = thread_count(me()).unwrap(); let _t = spawn_sleeping_thread(); assert!(thread_count(me()).unwrap() > n); }
#[test] fn open_file_is_listed() { let f = tempfile_in_scratch(); assert!(open_fds(me()).unwrap().iter().any(|e| matches!(e, FdEntry::File{path,..} if path == f.path))); }
#[test] fn tcp_listener_is_listed() { let l = TcpListener::bind("127.0.0.1:0").unwrap(); let port = l.local_addr().unwrap().port(); assert!(open_fds(me()).unwrap().iter().any(|e| matches!(e, FdEntry::Socket{local, state, ..} if local.ends_with(&format!(":{port}")) && state == "LISTEN"))); }
#[test] fn threads_have_ids() { assert!(threads(me()).unwrap().iter().all(|t| t.id != 0)); }
#[test] fn libsystem_is_mapped() { assert!(!mapped_files(me()).unwrap().is_empty()); }
#[test] fn own_args_env_cwd() { let x = proc_extra(me()).unwrap(); assert!(!x.args.is_empty()); assert!(x.env.iter().any(|(k,_)| k == "PATH")); assert_eq!(x.cwd.unwrap(), std::env::current_dir().unwrap().to_str().unwrap()); }
#[test] fn launchd_needs_root() { if unsafe { libc::geteuid() } != 0 { assert!(matches!(open_fds(1), Err(DetailError::AccessDenied))); } }
#[test] fn details_of_exited_process_is_no_such_process() { let mut c = Command::new("true").spawn().unwrap(); let pid = c.id() as i32; c.wait().unwrap(); assert!(matches!(open_fds(pid), Err(DetailError::NoSuchProcess))); }
#[test] fn start_time_is_recent_for_child() { /* spawn sleep 5 → start_time within 5 s of now; kill child */ }
```
Unit test in `libproc.rs`: `map_errno(libc::EPERM)` → AccessDenied, `ESRCH` → NoSuchProcess.

- [ ] **Step 2:** `cargo test --test darwin` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --test darwin` → PASS. (If `launchd_needs_root` reports something other than AccessDenied, fix `map_errno` mapping — libproc can return 0 with errno EPERM.)
- [ ] **Step 5: Checkpoint** — full `cargo test`.

---

### Task 4: Local sampler

**Files:** Create `src/sampler.rs`; extend `tests/darwin.rs`

**Interfaces:**
- Consumes: `darwin::libproc::thread_count`, model.
- Produces: `pub struct LocalSampler` — `pub fn new() -> Self`, `pub fn sample(&mut self) -> Snapshot`.

Use one long-lived `sysinfo::System` + `Networks`, refreshing only processes (cpu, memory, disk usage, user, exe), global CPU and memory — no full `refresh_all`. `cpu` from sysinfo process cpu_usage (already per-core %). `threads` = `thread_count(pid).ok()`. System `disk_*_bps` = sum of per-process disk deltas / elapsed; `net_*_bps` from Networks deltas / elapsed. `user` via sysinfo `Users` lookup (cache it; refresh only on unknown uid).

- [ ] **Step 1: Failing tests:** `snapshot_contains_self_with_parent` (own pid present, `ppid == getppid()`, `threads >= 1`, `mem > 0`), `child_appears_under_parent` (spawn `sleep 5`, sample, child ppid == me), `second_sample_has_cpu_for_busy_thread` (spin a thread 1.5 s between two samples → own `cpu > 20.0`), `system_totals_sane` (`mem_total > mem_used > 0`, `0.0 <= cpu <= 100.0`).
- [ ] **Step 2:** `cargo test --test darwin sampler` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Checkpoint** — full `cargo test`. Also print `sample()` wall time over 10 calls in a `#[ignore]` bench test; must be < 30 ms average on this machine (feeds the CPU budget).

---

### Task 5: Actions

**Files:** Create `src/actions.rs`; extend `tests/darwin.rs`

**Interfaces:**
- Consumes: `darwin::libproc::start_time`, `map_errno`, `Sig`.
- Produces:
  - `pub fn send_signal(pid: Pid, expected_start: u64, sig: Sig) -> Result<(), DetailError>` — reads `start_time(pid)`; mismatch → `Err(NoSuchProcess)` without signalling.
  - `pub fn renice(pid: Pid, expected_start: u64, nice: i32) -> Result<(), DetailError>` — same check, then `setpriority(PRIO_PROCESS)`; nice clamped to −20..=20.
  - `pub fn reveal_in_finder(path: &Path) -> std::io::Result<()>` — `open -R <path>`.

Kill-tree is not a function here: the UI calls `tree::descendants_postorder` then `send_signal` per pid with each pid's own start time.

- [ ] **Step 1: Failing tests:** `stop_cont_kill_child` (spawn `sleep 30`; Stop → status `T` via `ps -o stat= -p` with `LC_ALL=C`; Cont → not `T`; Kill → `wait()` shows signal 9), `signal_refuses_mismatched_start_time` (spawn child, call with `start+1` → `Err(NoSuchProcess)` and child still alive), `renice_child_up` (nice 10 → `ps -o nice=` shows 10), `renice_down_without_root_is_access_denied` (skip if root).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Checkpoint** — full `cargo test`.

---

### Task 6: Backend trait, LocalBackend, root helper

**Files:** Create `src/backend.rs`, `src/helper.rs`; tests inline in `helper.rs`

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces (`backend.rs`):

```rust
pub trait Backend: Send {
    fn sample(&mut self) -> Result<Snapshot, DetailError>;
    fn open_fds(&mut self, pid: Pid) -> Result<Vec<FdEntry>, DetailError>;
    fn threads(&mut self, pid: Pid) -> Result<Vec<ThreadEntry>, DetailError>;
    fn mapped_files(&mut self, pid: Pid) -> Result<Vec<String>, DetailError>;
    fn proc_extra(&mut self, pid: Pid) -> Result<ProcExtra, DetailError>;
    fn signal(&mut self, pid: Pid, start: u64, sig: Sig) -> Result<(), DetailError>;
    fn renice(&mut self, pid: Pid, start: u64, nice: i32) -> Result<(), DetailError>;
    fn privileged(&self) -> bool;
}
pub struct LocalBackend { /* LocalSampler */ }  // pub fn new() -> Self; privileged() = geteuid()==0
```

- Produces (`helper.rs`):
  - `#[derive(Serialize, Deserialize)] pub enum Request { Sample, OpenFds(Pid), Threads(Pid), MappedFiles(Pid), ProcExtra(Pid), Signal(Pid, u64, Sig), Renice(Pid, u64, i32) }` and `pub enum Response { Snapshot(Snapshot), Fds(Vec<FdEntry>), Threads(Vec<ThreadEntry>), Files(Vec<String>), Extra(ProcExtra), Done, Err(DetailError) }` — newline-delimited JSON.
  - `pub fn prepare_dir() -> io::Result<(PathBuf, String)>` — new dir under `$TMPDIR` mode 0700, random 32-byte hex token written to `<dir>/token` mode 0600.
  - `pub fn run_server(dir: &Path) -> io::Result<()>` — read and delete `<dir>/token`; bind `<dir>/sock`; accept one connection within 30 s (else exit); reject unless `getpeereid` uid == owner uid of `dir` and first line == token; serve requests with a `LocalBackend` until EOF; remove socket; return.
  - `pub struct HelperClient` — `pub fn connect(dir: &Path, token: &str, timeout: Duration) -> io::Result<Self>` (retries until timeout, sends token line); `impl Backend for HelperClient` (any I/O error → `DetailError::Disconnected`, and every later call returns `Disconnected` immediately).
  - `pub fn launch(exe: &Path, dir: &Path) -> io::Result<()>` — runs exactly:
    `osascript -e 'on run argv' -e 'do shell script (quoted form of item 1 of argv) & " --helper " & (quoted form of item 2 of argv) & " >/dev/null 2>&1 &" with administrator privileges' -e 'end run' <exe> <dir>`; non-zero exit (user cancelled) → `Err`.
- `main.rs`: `procexp --helper <dir>` → `helper::run_server(dir)` then exit; otherwise GUI (stub until Task 10).

- [ ] **Step 1: Failing tests** (server runs in a thread as the current user — no root needed): `client_samples_through_server` (snapshot contains own pid), `wrong_token_is_rejected` (connect with bad token → first request errors), `client_reports_disconnected_after_server_exit` (drop server side → next call `Err(Disconnected)` within 1 s, no hang), `server_exits_when_client_drops` (server thread joins within 1 s), `token_file_removed_and_dir_private` (after connect, `<dir>/token` gone; dir mode `0o700`).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Checkpoint** — full `cargo test`.

---

### Task 7: Metadata — signing, description, icon, MetaCache

**Files:** Create `src/darwin/meta.rs`, `src/metacache.rs`

**Interfaces:**
- Produces (`meta.rs`):
  - `pub struct Signing { pub valid: bool, pub authority: Option<String>, pub team_id: Option<String>, pub company: Option<String>, pub platform: bool }`
  - `pub fn signing_info(path: &Path) -> Option<Signing>` — `SecStaticCodeCreateWithPath` → `SecStaticCodeCheckValidity` (valid) → `SecCodeCopySigningInformation(kSecCSSigningInformation)`: team id, platform identifier, leaf cert subject via `SecCertificateCopySubjectSummary`.
  - `pub fn company_from_subject(subject: &str, platform: bool) -> Option<String>` — `"Developer ID Application: Google LLC (EQHXZ8M8AV)"` → `Google LLC`; `"Apple Development: X (Y)"` → `X`; `"Software Signing"` or `platform` → `Apple Inc.`; unknown → `None`.
  - `pub fn bundle_root(exe: &Path) -> Option<PathBuf>` — nearest ancestor ending in `.app` whose child is `Contents`.
  - `pub fn bundle_description(bundle: &Path) -> Option<String>` — Info.plist `CFBundleDisplayName` else `CFBundleName`.
  - `pub fn icon_rgba(path: &Path, size: u32) -> Option<Vec<u8>>` — NSWorkspace `iconForFile` (bundle path if any, else exe), rendered to `size`×`size` RGBA.
- Produces (`metacache.rs`):
  - `pub struct Meta { pub description: Option<String>, pub company: Option<String>, pub signing: Option<Signing>, pub icon: Option<Arc<Vec<u8>>> }`
  - `pub struct MetaCache` — `pub fn new(repaint: Box<dyn Fn() + Send>) -> Self`, `pub fn get(&self, exe: &Path) -> Option<Arc<Meta>>` (non-blocking; `None` → enqueues), cache keyed by path. One worker thread at `QOS_CLASS_BACKGROUND` (`pthread_set_qos_class_self_np`); calls `repaint` when an item finishes. Icon size 32 (drawn at 16 pt on Retina).

- [ ] **Step 1: Failing tests:** `company_parsing` (the four cases above), `bundle_root_finds_app` (`/Applications/Safari.app/Contents/MacOS/Safari` → `/Applications/Safari.app`; `/bin/ls` → None), `safari_description` (`bundle_description(/System/Applications/Calculator.app)` → `Some("Calculator")` or localized — assert `is_some()`), `ls_is_apple_platform_signed` (`signing_info("/bin/ls")` valid, company `Apple Inc.`), `unsigned_file_is_not_valid` (copy a shell script to scratch → `valid == false` or `None`), `icon_has_right_size` (`icon_rgba("/System/Applications/Calculator.app", 32).len() == 32*32*4`), `metacache_eventually_fills` (`get` returns None then Some within 5 s).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Checkpoint** — full `cargo test`.

---

### Task 8: Window picker primitives

**Files:** Create `src/darwin/windows.rs`

**Interfaces:**
- Produces:
  - `pub struct WinInfo { pub owner_pid: Pid, pub layer: i32, pub x: f64, pub y: f64, pub w: f64, pub h: f64 }`
  - `pub fn pick_window(wins: &[WinInfo], x: f64, y: f64, exclude: Pid) -> Option<Pid>` — first (front-most) window with `layer == 0`, containing the point, `owner_pid != exclude`.
  - `pub fn on_screen_windows() -> Vec<WinInfo>` — `CGWindowListCopyWindowInfo(OnScreenOnly | ExcludeDesktopElements)`, front-to-back order preserved.
  - `pub fn global_mouse() -> (f64, f64)` — `CGEventGetLocation(CGEventCreate(NULL))` (same top-left global coordinates as window bounds).
  - `pub fn left_mouse_down() -> bool` — `CGEventSourceButtonState(CombinedSessionState, Left)`.

- [ ] **Step 1: Failing tests:** `picks_frontmost_containing` (two overlapping layer-0 windows → first), `skips_menu_layer_and_self` (layer 25 and own pid ignored), `miss_returns_none`, `on_screen_windows_runs` (call succeeds; no assertion on count — CI may be headless).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Checkpoint** — full `cargo test`.

---

### Task 9: Settings and VirusTotal

**Files:** Create `src/settings.rs`, `src/vt.rs`

**Interfaces:**
- Produces (`settings.rs`):
  - `#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)] pub enum Column { Name, Pid, Cpu, Mem, Threads, User, Description, Company, Vt }`
  - `pub struct Settings { pub interval_ms: u64, pub columns: Vec<Column>, pub flat: bool, pub vt_enabled: bool, pub vt_api_key: String }` — `Default`: `1000`, all columns except `Vt`, `false`, `false`, `""`.
  - `pub fn app_support_dir() -> PathBuf` — `$HOME/Library/Application Support/ProcessTree` (created on demand).
  - `pub fn load(path: &Path) -> Settings` (missing or corrupt → default), `pub fn save(&self, path: &Path) -> io::Result<()>` (file mode 0600).
- Produces (`vt.rs`):
  - `#[derive(Clone, Debug, PartialEq)] pub enum VtState { Pending, Querying, Unknown, Done { malicious: u32, total: u32 }, Error(String) }` — column text: `bekliyor`, `sorgulanıyor`, `bilinmiyor`, `"{malicious}/{total}"`, `hata`.
  - `pub enum VtOutcome { Done { malicious: u32, total: u32 }, Unknown, RateLimited, BadKey, Error(String) }`
  - `pub fn parse_response(status: u16, body: &str) -> VtOutcome` — 200: `data.attributes.last_analysis_stats`, malicious = `malicious`, total = `malicious + suspicious + undetected + harmless`; 404 → Unknown; 429 → RateLimited; 401/403 → BadKey; else Error.
  - `pub struct RateLimiter` — `pub fn new(per_min: u32, per_day: u32) -> Self`, `pub fn try_take(&mut self, now_unix: u64) -> bool`; day boundary = UTC midnight. Defaults 4 / 500.
  - `pub trait VtHttp: Send { fn get(&self, sha256: &str, key: &str) -> Result<(u16, String), String>; }` + `pub struct UreqHttp` (GET `https://www.virustotal.com/api/v3/files/{sha256}`, header `x-apikey`).
  - `pub struct VtService` — `pub fn new(cache_path: PathBuf, http: Box<dyn VtHttp>, key: String, repaint: Box<dyn Fn() + Send>) -> Self`, `pub fn enqueue(&self, exe: &Path)`, `pub fn prioritize(&self, exe: &Path)`, `pub fn state(&self, exe: &Path) -> VtState`, `pub fn set_key(&self, key: String)`.

Worker behaviour: dedupe by exe path; hash with sha2 at `QOS_CLASS_BACKGROUND`, remembering `(path, mtime, size) → sha` so unchanged files aren't rehashed; one HTTP call per unique sha; cache `sha → VtOutcome` and the limiter's day counter in `vt-cache.json` under `app_support_dir()` (survives restarts). RateLimited → keep item, pause 60 s. BadKey → state `Error("API anahtarı geçersiz")` for all pending, stop until `set_key`. Network error → `Error(msg)`, item re-queued after 5 min. Files that can't be read → `Error("okunamadı")`, not retried. No request is ever made when `vt_enabled` is false (the UI does not construct `VtService` then).

- [ ] **Step 1: Failing tests** (fake `VtHttp` recording calls, short test durations via injectable clock/pauses):
  `settings_roundtrip_and_0600`, `corrupt_settings_fall_back_to_default`, `parse_200` (fixture JSON with stats `{malicious:2,suspicious:1,undetected:60,harmless:9}` → `Done{2,72}`), `parse_404_unknown`, `limiter_4_per_minute` (5th take in same minute false, ok after 60 s), `limiter_500_per_day_resets_at_utc_midnight`, `same_binary_queried_once` (two paths, same content → one HTTP call), `cache_survives_restart` (new service with same cache path → Done without HTTP), `rate_limited_pauses_and_keeps_item`, `bad_key_stops_queue` (no further calls until `set_key`), `offline_retries_later`, `prioritize_moves_to_front`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Checkpoint** — full `cargo test`.

---

### Task 10: GUI — window, sampler thread, toolbar graphs, tree table, actions

**Files:** Create `src/ui/mod.rs`, `src/ui/toolbar.rs`, `src/ui/tree_view.rs`; modify `src/main.rs`

**Interfaces:**
- Consumes: everything above.
- Produces: `pub fn run() -> eframe::Result<()>` in `ui/mod.rs`; `pub fn comparator(col: Column, desc: bool, meta: &dyn Fn(&ProcInfo) -> (Option<String>, Option<String>, Option<VtState>)) -> impl Fn(&ProcInfo, &ProcInfo) -> Ordering` in `tree_view.rs` (ties broken by pid).

Behaviour:
- Window title `Process Tree`. Backend lives in `Arc<Mutex<Box<dyn Backend>>>`. Sampler thread: every `interval_ms` calls `sample()`, sends the snapshot over a channel, calls `ctx.request_repaint()`. UI repaints only on new data or input (no continuous repaint) — required for the CPU budget. When the window is minimized, skip metadata/icon requests.
- Toolbar (`toolbar.rs`): four mini graphs (CPU, Bellek, Disk, Ağ) from `Ring` (120 samples), current value as label using `fmt`; filter text box (placeholder `Ara: ad, PID veya yol`); `Ağaç / Liste` toggle; buttons `Yönetici modu`, `Nişangâh`, `Ayarlar` (wired in Task 12).
- Table (`tree_view.rs`): virtualized rows (`egui_extras::TableBuilder` or `ScrollArea::show_rows`); column headers in Turkish: `Süreç`, `PID`, `CPU %`, `Bellek`, `Thread`, `Kullanıcı`, `Açıklama`, `Şirket`, `VirusTotal`; click header → sort (second click toggles direction); right-click header → show/hide columns (saved in Settings). Name cell: indentation by depth + ▸/▾ toggle + 16 pt icon. Missing values show `—`.
- Row colours: New → green, Exited (ghost from `Tracker`) → red, Stopped → grey, uid == own uid → light blue, uid 0 or < 500 → pink, else default. Highlight 3 s.
- Keyboard: ↑/↓/PgUp/PgDn/Home/End, ←/→ fold, Enter = properties, Delete = Sonlandır.
- Context menu: `Sonlandır`, `Zorla sonlandır`, `Ağacı sonlandır`, `Duraklat` / `Devam ettir` (by status), `Öncelik…` (slider −20..20), `Finder'da göster`, `Özellikler`, `VirusTotal'da şimdi kontrol et` (only when VT on). Destructive items open a modal: `"{name} ({pid}) sonlandırılsın mı?"` / tree: `"{name} ({pid}) ve {n} alt süreç sonlandırılsın mı?"`, buttons `Sonlandır` / `Vazgeç`. Errors from actions appear as a status-bar message with `DetailError` text.
- Selection is kept by `(pid, start_time)` across refreshes.

- [ ] **Step 1: Failing tests** for `comparator`: `sort_by_cpu_desc`, `sort_by_company_puts_none_last`, `ties_broken_by_pid`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement module + UI.
- [ ] **Step 4:** `cargo test` PASS; `cargo run --release` → window opens, tree shows `launchd` subtree, sorting/filter/fold work, a spawned `sleep 600` from a terminal appears green, killing it from the app (with confirmation) turns it red then removes it.
- [ ] **Step 5: Checkpoint** — full `cargo test`.

---

### Task 11: GUI — detail tabs and properties window

**Files:** Create `src/ui/details.rs`, `src/ui/properties.rs`; modify `src/ui/mod.rs`

**Interfaces:**
- Consumes: `Backend` detail methods, `MetaCache`, `Ring`.
- Produces: per-process history `HashMap<(Pid, u64), (Ring<f32>, Ring<u64>)>` kept in `App` (120 samples cpu / mem, dropped when the process leaves ghosts).

Behaviour:
- Bottom panel (resizable, toggled with `Ctrl+L`) with tabs `Dosyalar ve Soketler`, `Kütüphaneler`, `Thread'ler`, `Ağ`. Data fetched for the selected process only, off the UI thread, refreshed every interval while visible. `Ağ` = `FdEntry::Socket` with Tcp*/Udp* from `open_fds`; columns `Protokol`, `Yerel`, `Uzak`, `Durum`.
- Errors render as a centered message with `DetailError` Display text; exited process → `Süreç sonlandı`.
- Properties window (Enter / double click / menu), one per process, multiple allowed: sections `Genel` (yol, komut satırı, çalışma klasörü, başlama zamanı (local time), ebeveyn (clickable → selects it), kullanıcı), `Ortam` (env table), `İmza` (geçerli mi, imzalayan, Team ID, şirket), `Performans` (CPU and memory line graphs from per-process history), and a `Finder'da göster` button.

- [ ] **Step 1:** No new pure logic → no new unit tests; keep `cargo test` green.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Manual check with `cargo run --release`: select own terminal's `zsh` → files tab lists its tty; select a browser → Ağ tab shows ESTABLISHED connections; select `launchd` → `Erişim yok — Yönetici modunu açın`; open properties on `sleep 600`, kill it from a terminal → window shows `Süreç sonlandı`, no panic.
- [ ] **Step 4: Checkpoint** — full `cargo test`.

---

### Task 12: GUI — Yönetici modu, Nişangâh, Ayarlar, VirusTotal column

**Files:** Modify `src/ui/mod.rs`, `src/ui/toolbar.rs`, `src/ui/tree_view.rs`

Behaviour:
- `Yönetici modu`: `prepare_dir` → `launch(current_exe, dir)` → `HelperClient::connect(dir, token, 30 s)` → swap the backend. Toolbar shows `Yönetici` badge while privileged. Cancelled password → status message `Yönetici modu iptal edildi`. Any `Disconnected` from the backend → swap back to `LocalBackend`, status `Yönetici bağlantısı koptu — normal moda dönüldü`. Closing the app drops the client so the helper exits.
- `Nişangâh`: press-and-drag on the button enters picking mode (cursor crosshair, `request_repaint` each frame while picking); each frame poll `left_mouse_down()`; on release take `global_mouse()` and `pick_window(on_screen_windows(), x, y, own_pid)`; select that pid (expand its ancestors, scroll to it). No hit → status `Pencere bulunamadı`.
- `Ayarlar` window: `Yenileme aralığı` (500–5000 ms), `VirusTotal kontrolü` checkbox with note `Yalnızca dosya özeti (SHA-256) gönderilir.`, `API anahtarı` password field. Turning VT on (with non-empty key) creates `VtService` with `UreqHttp`, enqueues every visible exe, shows the `VirusTotal` column; turning it off drops the service and hides the column. Saved via `Settings::save`.
- VT column text from `VtState`; `Done` with `malicious > 0` in red. Menu item `VirusTotal'da şimdi kontrol et` → `prioritize`.

- [ ] **Step 1:** Implement.
- [ ] **Step 2:** Manual check: Yönetici modu → password prompt → `launchd` files tab now fills; `sudo pkill -f -- '--helper'` → app falls back within one interval with the status message; Nişangâh dragged onto a Finder window selects `Finder`; VT on with a real key → column moves from `bekliyor` to `x/y` for the first items, restart keeps results.
- [ ] **Step 3: Checkpoint** — full `cargo test`.

---

### Task 13: Packaging, install, CPU budget

**Files:** Create `procexp/bundle.sh`; modify `build.sh` (line `APP=...` → `"$HOME/Applications/Process Tree (Terminal).app"` so the old Python wrapper no longer overwrites the new app)

`bundle.sh` (sh, `set -e`): `cargo build --release`; create `Process Tree.app/Contents/{MacOS,Resources}`, copy binary as `MacOS/procexp`, write `Info.plist` with `CFBundleName=Process Tree`, `CFBundleIdentifier=local.processtree`, `CFBundleExecutable=procexp`, `LSMinimumSystemVersion=13.0`, `NSHighResolutionCapable=true`; `codesign --force -s -`; replace `~/Applications/Process Tree.app`; print the path.

- [ ] **Step 1:** Run `./bundle.sh` → prints `Kuruldu: …/Process Tree.app`; `codesign --verify` passes.
- [ ] **Step 2:** `open "~/Applications/Process Tree.app"` → window appears, no Terminal.
- [ ] **Step 3: CPU budget** — with the app in front and untouched: `ps -o %cpu= -p $(pgrep -x procexp)` sampled every 5 s for 60 s, average **< 5**; minimized: average **< 2**. If over, profile (`sample procexp 5`) and fix before calling it done.
- [ ] **Step 4:** Under `LC_ALL=tr_TR.UTF-8 open …` the app starts and numbers show with `.`.
- [ ] **Step 5: Checkpoint** — full `cargo test`; report the measured CPU numbers.
