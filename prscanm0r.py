#!/usr/bin/env python3
# Copyright (C) 2026 mr.computer
#
# Project: PRSCANM0R
# Author: mr.computer
# Email: IT_IRhackeyTEM@proton.me
# Website: https://mestercomputer.blogix.ir
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""PRSCANM0R - fast, rate-limited free-proxy collector & checker (GUI + CLI) for Debian."""
import argparse, csv, json, os, queue, random, re, socket, sys, threading, time
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run: sudo apt install python3-requests python3-socks python3-tk")

APP, VERSION = "PRSCANM0R", "1.0.0"
CFG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / APP
CFG_FILE = CFG_DIR / "config.json"
UA = "Mozilla/5.0 (X11; Linux x86_64) PRSCANM0R/" + VERSION

DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
]
TEST_URLS = [
    "https://ipwho.is/",
    "https://api.ipify.org?format=json",
    "http://ip-api.com/json/?fields=status,country,query",
]
DEFAULTS = {
    "custom_sources": [], "disabled_sources": [],
    "workers": 150, "timeout": 7.0, "tcp_timeout": 3.0,
    "rate": 25.0, "jitter_ms": 150, "source_delay": 1.0,
    "cache_ttl_min": 10, "max_proxies": 0,
    "protocols": ["http", "https", "socks4", "socks5"],
    "test_urls": TEST_URLS,
}

# ───────────────────────── config ─────────────────────────
def load_cfg():
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        cfg.update(json.loads(CFG_FILE.read_text()))
    except Exception:
        pass
    return cfg

def save_cfg(cfg):
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    CFG_FILE.write_text(json.dumps(cfg, indent=2))

def all_sources(cfg):
    return [(u, True) for u in DEFAULT_SOURCES] + [(u, False) for u in cfg["custom_sources"]]

# ───────────────────────── core ─────────────────────────
LINE = re.compile(r"^(?:(https?|socks[45])://)?((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})")

def parse(text, protos):
    out = set()
    for ln in text.splitlines():
        m = LINE.match(ln.strip())
        if not m:
            continue
        p, ip, port = m.group(1) or "http", m.group(2), int(m.group(3))
        if p in protos and port <= 65535 and all(int(x) <= 255 for x in ip.split(".")):
            out.add((p, ip, port))
    return out

def fetch_source(url, ttl_min, log, stop):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    f = CACHE_DIR / (re.sub(r"\W+", "_", url)[-120:] + ".txt")
    if f.exists() and time.time() - f.stat().st_mtime < ttl_min * 60:
        log(f"cache hit  {url}")
        return f.read_text(errors="ignore")
    for attempt in range(3):
        if stop.is_set():
            break
        try:
            r = requests.get(url, timeout=20, headers={"User-Agent": UA})
            if r.status_code == 429 or r.status_code >= 500:
                try:
                    wait = int(r.headers.get("Retry-After", ""))
                except ValueError:
                    wait = 2 ** (attempt + 1)
                log(f"HTTP {r.status_code} from source, waiting {min(wait, 30)}s")
                stop.wait(min(wait, 30))
                continue
            r.raise_for_status()
            f.write_text(r.text)
            return r.text
        except Exception as e:
            log(f"fetch failed ({e.__class__.__name__}) {url}")
            stop.wait(2 ** attempt)
    if f.exists():
        log(f"using stale cache for {url}")
        return f.read_text(errors="ignore")
    return ""

class RateLimiter:
    """Global request pacing: at most `rate` tests/second plus random jitter."""
    def __init__(self, rate, jitter_ms):
        self.iv = 1.0 / rate if rate > 0 else 0.0
        self.j = jitter_ms / 1000.0
        self.lock, self.next = threading.Lock(), 0.0

    def wait(self, stop):
        with self.lock:
            now = time.monotonic()
            t = max(now, self.next)
            self.next = t + self.iv
        d = t - now + random.uniform(0, self.j)
        if d > 0:
            stop.wait(d)

SCHEME = {"http": "http", "https": "http", "socks4": "socks4", "socks5": "socks5h"}

def check_one(p, cfg, rl, stop, idx):
    proto, ip, port = p
    try:  # stage 1: cheap TCP pre-check (no rate-limit cost, kills ~90% of dead proxies)
        socket.create_connection((ip, port), timeout=cfg["tcp_timeout"]).close()
    except OSError:
        return None
    rl.wait(stop)  # stage 2: paced HTTP test
    if stop.is_set():
        return None
    url = f"{SCHEME[proto]}://{ip}:{port}"
    urls = cfg["test_urls"]
    for k in range(min(2, len(urls))):  # rotate endpoints; fall back if one is rate-limited
        s = time.perf_counter()
        try:
            r = requests.get(urls[(idx + k) % len(urls)], proxies={"http": url, "https": url},
                             timeout=cfg["timeout"], headers={"User-Agent": UA})
            if r.status_code == 429:
                continue
            d = r.json()
            if d.get("success") is False or d.get("status") == "fail":
                return None
            rip = d.get("ip") or d.get("query")
            if not rip:
                return None
            return {"proxy": f"{ip}:{port}", "proto": proto, "ip": rip,
                    "country": d.get("country") or "?",
                    "latency": round((time.perf_counter() - s) * 1000)}
        except Exception:
            return None
    return None

class Checker:
    def __init__(self, cfg, emit):
        self.cfg, self.emit = cfg, emit
        self.stop, self.results, self.thread = threading.Event(), [], None

    def start(self):
        self.stop.clear()
        self.results = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        cfg, log = self.cfg, (lambda m: self.emit("log", m))
        try:
            items = set()
            srcs = [u for u, _ in all_sources(cfg) if u not in cfg["disabled_sources"]]
            for i, u in enumerate(srcs):
                if self.stop.is_set():
                    break
                found = parse(fetch_source(u, cfg["cache_ttl_min"], log, self.stop), cfg["protocols"])
                log(f"{len(found):>7} proxies  {u}")
                items |= found
                if i < len(srcs) - 1:
                    self.stop.wait(cfg["source_delay"])
            items = list(items)
            random.shuffle(items)
            if cfg["max_proxies"] > 0:
                items = items[: int(cfg["max_proxies"])]
            total = len(items)
            log(f"unique proxies to test: {total}")
            self.emit("total", total)
            q = queue.Queue()
            for i, p in enumerate(items):
                q.put((i, p))
            rl = RateLimiter(cfg["rate"], cfg["jitter_ms"])
            lock, st = threading.Lock(), {"done": 0, "alive": 0}

            def worker():
                while not self.stop.is_set():
                    try:
                        i, p = q.get_nowait()
                    except queue.Empty:
                        return
                    r = check_one(p, cfg, rl, self.stop, i)
                    with lock:
                        st["done"] += 1
                        d = st["done"]
                        if r:
                            st["alive"] += 1
                            self.results.append(r)
                        a = st["alive"]
                    if r:
                        self.emit("result", r)
                    if d % 10 == 0 or d == total:
                        self.emit("progress", (d, a))

            ts = [threading.Thread(target=worker, daemon=True)
                  for _ in range(max(1, min(int(cfg["workers"]), total)))]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            self.results.sort(key=lambda r: r["latency"])
        except Exception as e:
            log(f"error: {e}")
        finally:
            self.emit("done", len(self.results))

def write_results(path, results, fmt):
    results = sorted(results, key=lambda r: r["latency"])
    with open(path, "w", newline="") as f:
        if fmt == "json":
            json.dump(results, f, indent=2, ensure_ascii=False)
        elif fmt == "csv":
            w = csv.DictWriter(f, fieldnames=["proxy", "proto", "ip", "country", "latency"])
            w.writeheader()
            w.writerows(results)
        elif fmt == "plain":
            for r in results:
                f.write(f"{r['proto']}://{r['proxy']}\n")
        else:
            for r in results:
                f.write(f"{r['proxy']} | IP={r['ip']} | Country={r['country']} | Latency={r['latency']}ms\n")

# ───────────────────────── GUI ─────────────────────────
def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    cfg = load_cfg()
    BG, PN, FG, MUT, AC, OK = "#0d1117", "#161b22", "#e6edf3", "#8b949e", "#2f81f7", "#3fb950"
    root = tk.Tk()
    root.title(f"PRSCANM0R {VERSION}")
    root.geometry("1020x700")
    root.minsize(860, 560)
    root.configure(bg=BG)
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=FG, fieldbackground=PN, bordercolor="#30363d",
                lightcolor=PN, darkcolor=PN, troughcolor=PN, font=("DejaVu Sans", 10))
    s.configure("TNotebook", background=BG, borderwidth=0)
    s.configure("TNotebook.Tab", padding=(18, 8), background=PN, foreground=MUT)
    s.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", FG)])
    s.configure("TButton", padding=(14, 7), background="#21262d", foreground=FG)
    s.map("TButton", background=[("active", "#30363d")])
    s.configure("Accent.TButton", background=AC, foreground="white", font=("DejaVu Sans", 10, "bold"))
    s.map("Accent.TButton", background=[("active", "#1f6feb"), ("disabled", "#21262d")])
    s.configure("Treeview", background=PN, fieldbackground=PN, foreground=FG, rowheight=26, borderwidth=0)
    s.configure("Treeview.Heading", background="#21262d", foreground=FG, padding=6, font=("DejaVu Sans", 10, "bold"))
    s.map("Treeview", background=[("selected", AC)])
    s.configure("Horizontal.TProgressbar", background=OK, troughcolor=PN, thickness=10)
    s.configure("Stat.TLabel", background=PN, foreground=FG, font=("DejaVu Sans", 15, "bold"))
    s.configure("StatCap.TLabel", background=PN, foreground=MUT, font=("DejaVu Sans", 9))
    s.configure("TCheckbutton", background=BG)

    ev = queue.Queue()
    S = {"chk": None, "total": 0, "t0": 0.0, "rows": [], "sort": ("latency", False), "running": False}

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=12, pady=12)
    tab_d, tab_s, tab_c, tab_l = (ttk.Frame(nb, padding=12) for _ in range(4))
    for t, n in ((tab_d, "Dashboard"), (tab_s, "Sources"), (tab_c, "Settings"), (tab_l, "Log")):
        nb.add(t, text=n)

    # ---- dashboard
    bar = ttk.Frame(tab_d)
    bar.pack(fill="x")
    btn_start = ttk.Button(bar, text="▶  Start", style="Accent.TButton")
    btn_stop = ttk.Button(bar, text="■  Stop", state="disabled")
    btn_start.pack(side="left")
    btn_stop.pack(side="left", padx=8)
    fvar = tk.StringVar()
    ttk.Label(bar, text="Filter:", foreground=MUT).pack(side="right", padx=(0, 6))
    fe = ttk.Entry(bar, textvariable=fvar, width=22)
    fe.pack(side="right")
    ttk.Label(bar, text="  ").pack(side="right")

    cards = ttk.Frame(tab_d)
    cards.pack(fill="x", pady=10)
    stat = {}
    for i, k in enumerate(("Total", "Tested", "Alive", "Speed", "ETA")):
        c = tk.Frame(cards, bg=PN, padx=14, pady=8)
        c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
        cards.columnconfigure(i, weight=1)
        stat[k] = ttk.Label(c, text="–", style="Stat.TLabel")
        stat[k].pack(anchor="w")
        ttk.Label(c, text=k, style="StatCap.TLabel").pack(anchor="w")
    pb = ttk.Progressbar(tab_d, mode="determinate")
    pb.pack(fill="x", pady=(0, 10))

    cols = ("n", "proxy", "proto", "ip", "country", "latency")
    heads = {"n": "#", "proxy": "Proxy", "proto": "Type", "ip": "Exit IP", "country": "Country", "latency": "Latency (ms)"}
    wid = {"n": 50, "proxy": 190, "proto": 80, "ip": 160, "country": 160, "latency": 110}
    wrap = ttk.Frame(tab_d)
    wrap.pack(fill="both", expand=True)
    tv = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="extended")
    vs = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
    tv.configure(yscrollcommand=vs.set)
    tv.pack(side="left", fill="both", expand=True)
    vs.pack(side="right", fill="y")
    for c in cols:
        tv.heading(c, text=heads[c], command=lambda c=c: sort_by(c))
        tv.column(c, width=wid[c], anchor="w")

    foot = ttk.Frame(tab_d)
    foot.pack(fill="x", pady=(10, 0))
    status = ttk.Label(foot, text="Ready.", foreground=MUT)
    status.pack(side="left")
    for fmt, lbl in (("json", "JSON"), ("csv", "CSV"), ("plain", "URL list"), ("txt", "TXT")):
        ttk.Button(foot, text=f"Export {lbl}", command=lambda f=fmt: export(f)).pack(side="right", padx=(6, 0))
    ttk.Button(foot, text="Copy selected", command=lambda: copy_sel()).pack(side="right", padx=(6, 0))

    def match(r):
        q = fvar.get().strip().lower()
        return not q or q in f"{r['proxy']} {r['proto']} {r['ip']} {r['country']}".lower()

    def row(i, r):
        return (i, r["proxy"], r["proto"], r["ip"], r["country"], r["latency"])

    def refresh():
        tv.delete(*tv.get_children())
        key, rev = S["sort"]
        rows = sorted(S["rows"], key=lambda r: (r[key] if key != "n" else 0), reverse=rev)
        for i, r in enumerate((r for r in rows if match(r)), 1):
            tv.insert("", "end", values=row(i, r))

    def sort_by(c):
        if c == "n":
            return
        S["sort"] = (c, not S["sort"][1] if S["sort"][0] == c else False)
        refresh()

    fvar.trace_add("write", lambda *a: refresh())

    def export(fmt):
        if not S["rows"]:
            return messagebox.showinfo("PRSCANM0R", "No working proxies to export yet.")
        ext = {"json": ".json", "csv": ".csv", "plain": ".txt", "txt": ".txt"}[fmt]
        p = filedialog.asksaveasfilename(defaultextension=ext, initialfile=f"working-proxies{ext}")
        if p:
            write_results(p, [r for r in S["rows"] if match(r)], fmt)
            status.config(text=f"Saved: {p}")

    def copy_sel():
        items = [tv.item(i)["values"] for i in tv.selection()] or [tv.item(i)["values"] for i in tv.get_children()]
        root.clipboard_clear()
        root.clipboard_append("\n".join(f"{v[2]}://{v[1]}" for v in items))
        status.config(text=f"Copied {len(items)} proxies to clipboard")

    # ---- sources tab
    ttk.Label(tab_s, text="Default sources are always kept (you can disable them). Add your own raw list URLs below.",
              foreground=MUT).pack(anchor="w", pady=(0, 8))
    sw = ttk.Frame(tab_s)
    sw.pack(fill="both", expand=True)
    sv = ttk.Treeview(sw, columns=("state", "kind", "url"), show="headings", selectmode="browse")
    for c, t, w in (("state", "State", 80), ("kind", "Kind", 80), ("url", "URL", 600)):
        sv.heading(c, text=t)
        sv.column(c, width=w, anchor="w")
    sv.pack(fill="both", expand=True)
    ar = ttk.Frame(tab_s)
    ar.pack(fill="x", pady=10)
    uvar = tk.StringVar()
    ttk.Entry(ar, textvariable=uvar).pack(side="left", fill="x", expand=True)
    ttk.Button(ar, text="Add", style="Accent.TButton", command=lambda: src_add()).pack(side="left", padx=6)
    ttk.Button(ar, text="Enable/Disable", command=lambda: src_toggle()).pack(side="left")
    ttk.Button(ar, text="Remove custom", command=lambda: src_remove()).pack(side="left", padx=6)

    def src_refresh():
        sv.delete(*sv.get_children())
        for u, d in all_sources(cfg):
            sv.insert("", "end", iid=u, values=("off" if u in cfg["disabled_sources"] else "on",
                                                "default" if d else "custom", u))

    def src_add():
        u = uvar.get().strip()
        if not u.startswith(("http://", "https://")):
            return messagebox.showerror("PRSCANM0R", "URL must start with http:// or https://")
        if u in cfg["custom_sources"] or u in DEFAULT_SOURCES:
            return messagebox.showinfo("PRSCANM0R", "Source already exists.")
        cfg["custom_sources"].append(u)
        save_cfg(cfg)
        uvar.set("")
        src_refresh()

    def src_toggle():
        for u in sv.selection():
            (cfg["disabled_sources"].remove if u in cfg["disabled_sources"] else cfg["disabled_sources"].append)(u)
        save_cfg(cfg)
        src_refresh()

    def src_remove():
        for u in sv.selection():
            if u in cfg["custom_sources"]:
                cfg["custom_sources"].remove(u)
            else:
                messagebox.showinfo("PRSCANM0R", "Default sources can't be removed, only disabled.")
        save_cfg(cfg)
        src_refresh()

    # ---- settings tab
    FIELDS = [
        ("workers", "Concurrent workers", 10, 1000, 10, int),
        ("timeout", "HTTP test timeout (s)", 1, 60, 1, float),
        ("tcp_timeout", "TCP pre-check timeout (s)", 0.5, 15, 0.5, float),
        ("rate", "Max tests per second (rate limit)", 1, 200, 1, float),
        ("jitter_ms", "Random jitter (ms)", 0, 2000, 50, int),
        ("source_delay", "Delay between sources (s)", 0, 30, 0.5, float),
        ("cache_ttl_min", "Source cache lifetime (min)", 0, 1440, 5, int),
        ("max_proxies", "Test at most N proxies (0 = all)", 0, 200000, 500, int),
    ]
    vars_ = {}
    g = ttk.Frame(tab_c)
    g.pack(anchor="w")
    for r_, (k, lbl, lo, hi, inc, _t) in enumerate(FIELDS):
        ttk.Label(g, text=lbl).grid(row=r_, column=0, sticky="w", pady=5, padx=(0, 24))
        vars_[k] = tk.StringVar(value=str(cfg[k]))
        ttk.Spinbox(g, from_=lo, to=hi, increment=inc, textvariable=vars_[k], width=10).grid(row=r_, column=1)
    pv = {p: tk.BooleanVar(value=p in cfg["protocols"]) for p in ("http", "https", "socks4", "socks5")}
    pf = ttk.Frame(tab_c)
    pf.pack(anchor="w", pady=14)
    ttk.Label(pf, text="Protocols:").pack(side="left", padx=(0, 14))
    for p, v in pv.items():
        ttk.Checkbutton(pf, text=p, variable=v).pack(side="left", padx=6)

    def save_settings():
        try:
            for k, _l, lo, hi, _i, t in FIELDS:
                v = t(vars_[k].get())
                cfg[k] = min(max(v, lo), hi)
                vars_[k].set(str(cfg[k]))
        except ValueError:
            return messagebox.showerror("PRSCANM0R", "Invalid number in settings.")
        cfg["protocols"] = [p for p, v in pv.items() if v.get()] or ["http"]
        save_cfg(cfg)
        status.config(text="Settings saved.")

    ttk.Button(tab_c, text="Save settings", style="Accent.TButton", command=save_settings).pack(anchor="w")
    ttk.Label(tab_c, foreground=MUT, wraplength=700, text=(
        "Tip: if you still see throttling, lower 'Max tests per second' (e.g. 10) and raise jitter. "
        "Dead proxies are filtered by the TCP pre-check first, so the rate limit only applies to "
        "proxies that are likely alive.")).pack(anchor="w", pady=14)

    # ---- log tab
    lw = ttk.Frame(tab_l)
    lw.pack(fill="both", expand=True)
    logt = tk.Text(lw, bg=PN, fg=FG, insertbackground=FG, relief="flat", state="disabled", font=("DejaVu Sans Mono", 9))
    ls = ttk.Scrollbar(lw, command=logt.yview)
    logt.configure(yscrollcommand=ls.set)
    logt.pack(side="left", fill="both", expand=True)
    ls.pack(side="right", fill="y")

    def log(m):
        logt.config(state="normal")
        logt.insert("end", time.strftime("%H:%M:%S ") + m + "\n")
        logt.see("end")
        logt.config(state="disabled")

    # ---- control
    def start():
        save_settings()
        S["rows"].clear()
        tv.delete(*tv.get_children())
        S.update(total=0, t0=time.time(), running=True)
        for k in stat:
            stat[k].config(text="–")
        pb.config(value=0)
        btn_start.config(state="disabled")
        btn_stop.config(state="normal")
        status.config(text="Collecting sources…")
        S["chk"] = Checker(cfg, lambda k, v: ev.put((k, v)))
        S["chk"].start()

    def stop():
        if S["chk"]:
            S["chk"].stop.set()
            status.config(text="Stopping…")

    btn_start.config(command=start)
    btn_stop.config(command=stop)

    def poll():
        prog = None
        for _ in range(500):
            try:
                k, v = ev.get_nowait()
            except queue.Empty:
                break
            if k == "log":
                log(v)
            elif k == "total":
                S["total"] = v
                stat["Total"].config(text=str(v))
                pb.config(maximum=max(v, 1))
                status.config(text="Testing…")
            elif k == "result":
                S["rows"].append(v)
                if match(v):
                    tv.insert("", "end", values=row(len(tv.get_children()) + 1, v))
            elif k == "progress":
                prog = v
            elif k == "done":
                S["running"] = False
                btn_start.config(state="normal")
                btn_stop.config(state="disabled")
                S["sort"] = ("latency", False)
                refresh()
                stat["Alive"].config(text=str(len(S["rows"])))
                status.config(text=f"Finished – {v} working proxies.")
        if prog and S["running"]:
            d, a = prog
            el = max(time.time() - S["t0"], 1e-6)
            sp = d / el
            stat["Tested"].config(text=str(d))
            stat["Alive"].config(text=str(a))
            stat["Speed"].config(text=f"{sp:.0f}/s")
            rem = (S["total"] - d) / sp if sp else 0
            stat["ETA"].config(text=f"{int(rem // 60)}m {int(rem % 60)}s")
            pb.config(value=d)
        root.after(100, poll)

    def close():
        if S["chk"]:
            S["chk"].stop.set()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close)
    src_refresh()
    poll()
    root.mainloop()

# ───────────────────────── CLI ─────────────────────────
def cmd_run(a):
    cfg = load_cfg()
    for k in ("workers", "timeout", "rate", "jitter_ms"):
        if getattr(a, k) is not None:
            cfg[k] = getattr(a, k)
    if a.max is not None:
        cfg["max_proxies"] = a.max
    if a.protocols:
        cfg["protocols"] = a.protocols.split(",")
    countries = {c.strip().lower() for c in a.country.split(",")} if a.country else None
    ok = lambda r: (not countries or r["country"].lower() in countries) and \
                   (not a.max_latency or r["latency"] <= a.max_latency)
    done = threading.Event()
    tot = {"n": 0}

    def emit(k, v):
        if k == "log" and not a.quiet:
            print(f"[*] {v}", file=sys.stderr)
        elif k == "total":
            tot["n"] = v
        elif k == "result" and ok(v):
            print(f"[+] {v['proxy']} | IP={v['ip']} | Country={v['country']} | Latency={v['latency']}ms", flush=True)
        elif k == "progress" and not a.quiet:
            print(f"\r[~] {v[0]}/{tot['n']} tested, {v[1]} alive", end="", file=sys.stderr, flush=True)
        elif k == "done":
            done.set()

    chk = Checker(cfg, emit)
    chk.start()
    try:
        while not done.wait(0.3):
            pass
    except KeyboardInterrupt:
        print("\n[!] Stopping… saving partial results", file=sys.stderr)
        chk.stop.set()
        done.wait(15)
    res = [r for r in chk.results if ok(r)]
    if a.best:
        res = sorted(res, key=lambda r: r["latency"])[: a.best]
    write_results(a.out, res, a.format)
    print(f"\n[*] Working proxies: {len(res)}\n[+] Output file: {a.out}")

def cmd_source(a):
    cfg = load_cfg()
    u = a.url
    if a.action == "list":
        for src, d in all_sources(cfg):
            print(f"{'off' if src in cfg['disabled_sources'] else 'on ':3}  {'default' if d else 'custom '}  {src}")
        return
    if a.action == "reset":
        cfg["custom_sources"], cfg["disabled_sources"] = [], []
    elif not u or not u.startswith(("http://", "https://")):
        sys.exit("Error: provide a URL starting with http:// or https://")
    elif a.action == "add":
        if u in cfg["custom_sources"] or u in DEFAULT_SOURCES:
            sys.exit("Source already exists.")
        cfg["custom_sources"].append(u)
    elif a.action == "remove":
        if u in DEFAULT_SOURCES:
            sys.exit("Default sources can't be removed; use: prscanm0r source disable URL")
        if u not in cfg["custom_sources"]:
            sys.exit("Source not found.")
        cfg["custom_sources"].remove(u)
    elif a.action == "disable":
        if u not in cfg["disabled_sources"]:
            cfg["disabled_sources"].append(u)
    elif a.action == "enable":
        if u in cfg["disabled_sources"]:
            cfg["disabled_sources"].remove(u)
    save_cfg(cfg)
    print("OK")

def cmd_config(a):
    cfg = load_cfg()
    if a.action == "show":
        print(json.dumps({k: v for k, v in cfg.items() if k not in ("custom_sources", "disabled_sources")}, indent=2))
    elif a.action == "reset":
        save_cfg(json.loads(json.dumps(DEFAULTS)))
        print("Reset to defaults (sources cleared).")
    else:
        if a.key not in DEFAULTS or a.key.endswith("_sources") or a.value is None:
            sys.exit(f"Usage: config set KEY VALUE  (keys: {', '.join(k for k in DEFAULTS if not k.endswith('_sources'))})")
        d = DEFAULTS[a.key]
        cfg[a.key] = [x.strip() for x in a.value.split(",")] if isinstance(d, list) else type(d)(a.value)
        save_cfg(cfg)
        print(f"{a.key} = {cfg[a.key]}")

def main():
    ap = argparse.ArgumentParser(prog=APP, description="PRSCANM0R – free proxy collector & checker (GUI + CLI)")
    ap.add_argument("-V", "--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("gui", help="open the graphical interface (default)")
    r = sub.add_parser("run", help="headless collect + test")
    r.add_argument("-o", "--out", default="working-proxies.txt")
    r.add_argument("-f", "--format", choices=["txt", "plain", "csv", "json"], default="txt")
    r.add_argument("-w", "--workers", type=int)
    r.add_argument("-t", "--timeout", type=float)
    r.add_argument("-r", "--rate", type=float, help="max tests per second")
    r.add_argument("--jitter-ms", dest="jitter_ms", type=int)
    r.add_argument("-n", "--max", type=int, help="test at most N proxies")
    r.add_argument("-p", "--protocols", help="comma list: http,https,socks4,socks5")
    r.add_argument("-c", "--country", help="keep only these countries, e.g. 'Germany,Iran'")
    r.add_argument("--max-latency", type=int, help="keep only proxies faster than N ms")
    r.add_argument("--best", type=int, help="keep only the N fastest")
    r.add_argument("-q", "--quiet", action="store_true")
    s = sub.add_parser("source", help="manage proxy-list sources")
    s.add_argument("action", choices=["list", "add", "remove", "enable", "disable", "reset"])
    s.add_argument("url", nargs="?")
    c = sub.add_parser("config", help="show/change settings")
    c.add_argument("action", choices=["show", "set", "reset"])
    c.add_argument("key", nargs="?")
    c.add_argument("value", nargs="?")
    a = ap.parse_args()
    if a.cmd in (None, "gui"):
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            ap.print_help()
            sys.exit("\nNo graphical display found. Use the CLI: prscanm0r run")
        try:
            run_gui()
        except ImportError:
            sys.exit("Tkinter missing. Run: sudo apt install python3-tk")
    else:
        {"run": cmd_run, "source": cmd_source, "config": cmd_config}[a.cmd](a)

if __name__ == "__main__":
    main()
