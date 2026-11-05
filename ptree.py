#!/usr/bin/env python3
"""ptree: macOS terminal task manager with a process tree. Stdlib only (curses + ps)."""
import curses
import os
import signal
import subprocess

REFRESH_MS = 2000


def read_procs():
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,user=,%cpu=,%mem=,rss=,comm="],
                         capture_output=True, text=True,
                         env={**os.environ, "LC_ALL": "C"}).stdout  # tr_TR'de ps "3,7" yazar
    procs = {}
    for line in out.splitlines():
        p = line.split(None, 6)  # comm is last and may contain spaces
        if len(p) < 7:
            continue
        procs[int(p[0])] = dict(pid=int(p[0]), ppid=int(p[1]), user=p[2], cpu=float(p[3]),
                                mem=float(p[4]), rss=int(p[5]), cmd=p[6])
    return procs


def parent_of(p, procs):
    return p["ppid"] if p["ppid"] in procs and p["ppid"] != p["pid"] else None


def build_rows(procs, collapsed=frozenset(), query=""):
    """Rows in tree order as (prefix, proc). With a query, keep matches plus their ancestors."""
    kids = {}
    for p in procs.values():
        kids.setdefault(parent_of(p, procs), []).append(p)
    keep = None
    if query:
        q, keep = query.lower(), set()
        for p in procs.values():
            if q in p["cmd"].lower() or q == str(p["pid"]):
                while p and p["pid"] not in keep:
                    keep.add(p["pid"])
                    p = procs.get(parent_of(p, procs))
    rows = []

    def walk(parent, prefix):
        children = [c for c in sorted(kids.get(parent, []), key=lambda c: c["pid"])
                    if keep is None or c["pid"] in keep]
        for i, c in enumerate(children):
            last = i == len(children) - 1
            has_kids = c["pid"] in kids
            mark = ("+" if c["pid"] in collapsed else "-") if has_kids else " "
            rows.append((prefix + ("└─" if last else "├─") + mark + " ", c))
            if c["pid"] not in collapsed:
                walk(c["pid"], prefix + ("  " if last else "│ "))

    walk(None, "")
    return rows


def ask(scr, prompt, echo=False):
    h, w = scr.getmaxyx()
    scr.move(h - 1, 0)
    scr.clrtoeol()
    scr.addnstr(h - 1, 0, prompt, w - 1, curses.A_BOLD)
    scr.timeout(-1)
    if echo:
        curses.echo()
        curses.curs_set(1)
        s = scr.getstr(h - 1, min(len(prompt), w - 2)).decode(errors="ignore")
        curses.noecho()
        curses.curs_set(0)
    else:
        k = scr.getch()
        s = chr(k) if 0 <= k < 256 else ""
    scr.timeout(REFRESH_MS)
    return s


def main(scr):
    curses.curs_set(0)
    curses.use_default_colors()
    scr.timeout(REFRESH_MS)
    collapsed, query, sel, top, msg, sel_pid = set(), "", 0, 0, "", None
    while True:
        procs = read_procs()
        rows = build_rows(procs, collapsed, query)
        pids = [r[1]["pid"] for r in rows]
        if sel_pid in pids:
            sel = pids.index(sel_pid)  # keep the cursor on the same process across refreshes
        sel = max(0, min(sel, len(rows) - 1))
        sel_pid = pids[sel] if rows else None
        h, w = scr.getmaxyx()
        body = max(1, h - 2)
        top = min(top, sel)
        top = max(top, sel - body + 1)

        scr.erase()
        head = f"{'PID':>6} {'USER':<12} {'CPU%':>5} {'MEM%':>5} {'RSS MB':>8}  COMMAND"
        scr.addnstr(0, 0, head.ljust(w), w - 1, curses.A_REVERSE | curses.A_BOLD)
        for y, (prefix, p) in enumerate(rows[top:top + body], start=1):
            line = (f"{p['pid']:>6} {p['user'][:12]:<12} {p['cpu']:>5.1f} {p['mem']:>5.1f} "
                    f"{p['rss'] / 1024:>8.1f}  {prefix}{os.path.basename(p['cmd']) or p['cmd']}")
            scr.addnstr(y, 0, line, w - 1, curses.A_REVERSE if top + y - 1 == sel else 0)
        foot = (f" {len(rows)}/{len(procs)} procs"
                + (f" | filter: {query}" if query else "")
                + " | ↑↓ PgUp/PgDn  ←→/Enter fold  / filter  Esc clear  t TERM  K KILL  q quit"
                + (f" | {msg}" if msg else ""))
        scr.addnstr(h - 1, 0, foot, w - 1, curses.A_DIM)
        scr.refresh()

        k = scr.getch()
        if k == -1:
            continue
        msg = ""
        if k in (ord("q"), ord("Q")):
            return
        elif k == curses.KEY_UP:
            sel -= 1
        elif k == curses.KEY_DOWN:
            sel += 1
        elif k == curses.KEY_PPAGE:
            sel -= body
        elif k == curses.KEY_NPAGE:
            sel += body
        elif k == curses.KEY_HOME:
            sel = 0
        elif k == curses.KEY_END:
            sel = len(rows) - 1
        elif k in (10, 13, ord(" ")) and sel_pid is not None:
            collapsed ^= {sel_pid}
        elif k == curses.KEY_LEFT and sel_pid is not None:
            collapsed.add(sel_pid)
        elif k == curses.KEY_RIGHT:
            collapsed.discard(sel_pid)
        elif k == ord("/"):
            query = ask(scr, "filter (name or pid): ", echo=True).strip()
        elif k == 27:
            query = ""
        elif k in (ord("t"), ord("K")) and sel_pid is not None:
            sig = signal.SIGTERM if k == ord("t") else signal.SIGKILL
            name = os.path.basename(procs[sel_pid]["cmd"])
            if ask(scr, f"Send {sig.name} to {sel_pid} ({name})? [y/N] ").lower() == "y":
                try:
                    os.kill(sel_pid, sig)
                    msg = f"{sig.name} -> {sel_pid}"
                except OSError as e:
                    msg = f"failed: {e.strerror} (try: sudo python3 ptree.py)"
        if k in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_PPAGE, curses.KEY_NPAGE,
                 curses.KEY_HOME, curses.KEY_END):
            sel = max(0, min(sel, len(rows) - 1))
            sel_pid = pids[sel] if rows else None


if __name__ == "__main__":
    os.environ.setdefault("ESCDELAY", "25")  # make Esc respond instantly
    curses.wrapper(main)
