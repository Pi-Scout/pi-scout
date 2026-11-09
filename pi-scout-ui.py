#!/usr/bin/env python3
"""Pi-Scout UI — a web dashboard for pi-scout.py.

pi-scout.py is imported and reused as-is (never modified): the same guards,
Gemini prompt, thresholds, blocklist format and decision log. This file only adds
a worker thread with events, a tiny stdlib HTTP server and the dashboard page.

    sudo python3 pi-scout-ui.py                      # all categories, aggression 7
    sudo python3 pi-scout-ui.py --ads --tracking     # only these categories (also toggles in the UI)

Stop the command-line pi-scout.py before running the UI live, so two processes
don't write the same blocklist.
"""
import os
import sys
import json
import time
import hmac
import socket
import sqlite3
import secrets
import argparse
import threading
import importlib.util
from collections import deque, defaultdict
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_PATH = "/var/tmp/pi_scout_ui_token"
ENGINE = None
TOKEN = ""
NO_AUTH = False


# --------------------------------------------------------------------------
# Loading the original script as a library
# --------------------------------------------------------------------------
def find_core(explicit):
    for p in (explicit, os.path.join(HERE, "pi-scout.py"), "/usr/local/bin/pi-scout.py"):
        if p and os.path.isfile(p):
            return p
    return None


def load_core(path):
    spec = importlib.util.spec_from_file_location("pi_scout_core", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # its __main__ block does not run on import
    return mod


def find_key(cli):
    if cli:
        return cli.strip()
    if os.environ.get("GEMINI_API_KEY"):
        return os.environ["GEMINI_API_KEY"].strip()
    homes = []
    if os.environ.get("SUDO_USER"):
        homes.append(os.path.expanduser("~" + os.environ["SUDO_USER"]))
    homes.append(os.path.expanduser("~"))
    for h in homes:
        p = os.path.join(h, ".gemini_key")
        if os.path.isfile(p):
            with open(p) as f:
                return f.read().strip()
    return ""


def get_token(arg):
    if arg:
        return arg
    try:
        with open(TOKEN_PATH) as f:
            t = f.read().strip()
        if t:
            return t
    except OSError:
        pass
    t = secrets.token_urlsafe(9)
    try:
        fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(t)
    except OSError:
        pass
    return t


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# --------------------------------------------------------------------------
# Engine: runs the live hunter / audit in a worker thread and records events
# --------------------------------------------------------------------------
class Busy(RuntimeError):
    """Raised when an action needs Pi-Scout to be idle but it is running."""


class Engine:
    def __init__(self, core, aggression=7, categories=None):
        self.ps = core
        self.aggression = aggression
        core.set_enabled(categories or core.CATEGORIES)
        self.lock = threading.RLock()
        self.fs_lock = threading.Lock()  # serialises blocklist writes (worker vs. Allow/Clear buttons)
        self.events = deque(maxlen=500)
        self.next_id = 1
        self.buckets = defaultdict(lambda: [0, 0])  # minute -> [blocked, refused]
        self.mode = "idle"
        self.stop = threading.Event()
        self.thread = None
        self.started_at = None
        self.stats = {"seen": 0, "batches": 0, "errors": 0, "wild": 0, "exact": 0, "rejected": 0}
        self.queue_len = 0
        self.audit = {"done": 0, "total": 0, "phase": "idle"}
        self.last_audit = None  # summary of the most recent history scan
        self.last_error = ""
        self.guard = None
        self.cache = {"t": 0.0, "wild": 0, "exact": 0, "never": [], "bycat": {}}

        orig_gravity = core.run_gravity

        def run_gravity():  # same behaviour, plus a feed event
            self.emit("gravity", "Updating Pi-hole gravity", "pihole -g")
            orig_gravity()

        core.run_gravity = run_gravity

    # ---- events -----------------------------------------------------------
    def emit(self, kind, title, detail="", **meta):
        with self.lock:
            ev = {"id": self.next_id, "ts": time.time(), "kind": kind, "title": title, "detail": detail, **meta}
            self.next_id += 1
            self.events.append(ev)
            if kind in ("block", "reject"):
                self.buckets[int(ev["ts"] // 60)][0 if kind == "block" else 1] += 1
        return ev

    def series(self):
        now_m = int(time.time() // 60)
        with self.lock:
            for k in [k for k in self.buckets if k < now_m - 120]:
                del self.buckets[k]
            return [list(self.buckets.get(m, (0, 0))) for m in range(now_m - 59, now_m + 1)]

    def refresh_cache(self):
        if time.time() - self.cache["t"] < 5:
            return
        try:
            ps = self.ps
            by_file = ps.load_blocks_by_file()
            bycat = {c: len(by_file[ps.category_path(c)][0]) + len(by_file[ps.category_path(c)][1]) for c in ps.CATEGORIES}
            self.cache.update(wild=sum(len(w) for w, _ in by_file.values()), exact=sum(len(e) for _, e in by_file.values()),
                              never=sorted(ps.load_never_block()), bycat=bycat)
        except Exception:
            pass
        self.cache["t"] = time.time()

    def state(self, since=0):
        ps = self.ps
        self.refresh_cache()
        wmin, emin = ps.thresholds(self.aggression)
        cats = {c: {"enabled": c in ps.ENABLED, "count": self.cache["bycat"].get(c, 0),
                    "file": os.path.basename(ps.category_path(c))} for c in ps.CATEGORIES}
        with self.lock:
            evs = [e for e in self.events if e["id"] > since][-200:]
            return {
                "mode": self.mode,
                "stopping": self.stop.is_set() and self.mode in ("live", "audit"),
                "aggression": self.aggression,
                "thresholds": {"wild": wmin, "exact": emin},
                "categories": cats,
                "model": ps.MODEL,
                "api_key": bool(os.environ.get("GEMINI_API_KEY")),
                "started_at": self.started_at,
                "stats": dict(self.stats),
                "queue": self.queue_len,
                "audit": dict(self.audit),
                "rules": {"wild": self.cache["wild"], "exact": self.cache["exact"]},
                "never": self.cache["never"][:40],
                "never_total": len(self.cache["never"]),
                "pihole_allow": len(self.guard.allow_exact) + len(self.guard.allow_regex) if self.guard else 0,
                "gravity": {"pending": ps._gravity_pending, "last": ps._last_gravity or None},
                "last_error": self.last_error,
                "last_audit": self.last_audit,
                "series": self.series(),
                "events": evs,
                "last_id": self.next_id - 1,
            }

    # ---- controls ---------------------------------------------------------
    def set_options(self, aggression=None, categories=None):
        if categories is not None:
            cats = {c for c in categories if c in self.ps.CATEGORIES}
            if not (cats - {"other"}):
                raise ValueError("Keep at least one of Ads, Tracking or Adult switched on")
            if cats != self.ps.ENABLED:
                self.ps.set_enabled(cats)
                self.emit("system", "Categories updated", self.ps.categories_label())
        if aggression is not None:
            self.aggression = max(1, min(10, int(aggression)))

    def start(self, mode):
        with self.lock:
            if self.mode == "clearing":
                return False, "Clearing lists; try again in a moment"
            if self.mode != "idle":
                return False, f"Already running ({self.mode})"
            if not os.environ.get("GEMINI_API_KEY"):
                return False, "Gemini API key missing — start with --key or set GEMINI_API_KEY"
            self.mode = mode
            self.stop.clear()
            self.started_at = time.time()
            self.thread = threading.Thread(target=self._run, args=(mode,), daemon=True)
            self.thread.start()
        return True, ""

    def request_stop(self):
        self.stop.set()

    def reset(self, cats):
        """Clear the chosen categories (and the judged-domains memory and retry queue tied to them).
        Only allowed while nothing is running; the engine stays in a 'clearing' state until gravity is done."""
        ps = self.ps
        cats = [c for c in ps.CATEGORIES if c in set(cats)]
        if not cats:
            return False, "Pick at least one category to clear"
        with self.lock:
            if self.mode != "idle":
                raise Busy("Stop Pi-Scout first: lists can only be cleared while nothing is running."
                           if self.mode in ("live", "audit") else "Pi-Scout is busy; try again in a moment.")
            self.mode = "clearing"
        try:
            with self.fs_lock:
                res = ps.reset_categories(cats)
            if self.guard:
                self.guard.refresh(force=True)
        except Exception as e:
            with self.lock:
                self.mode = "idle"
            return False, f"Could not clear: {e}"
        self.cache["t"] = 0.0
        label = "all categories" if len(cats) == len(ps.CATEGORIES) else ", ".join(c.title() for c in cats)
        n = sum(res["removed"].values())
        self.emit("reset", f"Cleared {label}",
                  f"{n} rule{'s' if n != 1 else ''} removed · {res['decided']} judged and {res['backlog']} queued domains forgotten")
        threading.Thread(target=self._finish_clear, daemon=True).start()
        return True, res

    def _finish_clear(self):
        try:
            with self.fs_lock:
                self.ps.request_gravity_now()
        except Exception as e:
            self.emit("error", "Gravity update failed", str(e)[:160])
        finally:
            with self.lock:
                self.mode = "idle"

    def allow(self, domain):
        ps = self.ps
        domain = (domain or "").lower().strip().rstrip(".")
        if not ps.valid_hostname(domain):
            return False, "That doesn't look like a valid hostname"
        try:
            with self.fs_lock:
                ps.run_allow(domain)
        except Exception as e:
            return False, f"Could not apply: {e}"
        if self.guard:
            self.guard.refresh(force=True)
        self.cache["t"] = 0.0
        self.emit("allow", domain, "Unblocked and added to the never-block list")
        return True, ""

    # ---- worker -----------------------------------------------------------
    def _run(self, mode):
        try:
            self._live() if mode == "live" else self._audit()
        except Exception as e:
            self.last_error = str(e)
            self.stats["errors"] += 1
            self.emit("error", "Worker stopped unexpectedly", str(e))
        finally:
            try:
                with self.fs_lock:
                    self.ps.maybe_run_gravity(force=True)  # ingest rules written but not yet loaded
            except Exception:
                pass
            with self.lock:
                self.mode = "idle"
                self.audit["phase"] = "idle"
                self.started_at = None
                self.queue_len = 0

    def _process(self, batch, guard, fam, decided):
        ps = self.ps
        guard.refresh()
        fam.refresh()
        preview = ", ".join(batch[:3]) + (f" +{len(batch) - 3} more" if len(batch) > 3 else "")
        self.emit("batch", f"Asking Gemini about {len(batch)} candidate{'s' if len(batch) != 1 else ''}", preview)
        decisions = ps.query_gemini(ps.build_groups(batch, fam, guard), self.aggression)
        accepted, rejected = ps.evaluate(decisions, batch, guard, fam, self.aggression)
        ps.log_decisions(accepted, rejected)
        for r in rejected:
            self.stats["rejected"] += 1
            self.emit("reject", r["value"], r["note"], conf=r["confidence"], sub=r["kind"], cat=r["category"])
        with self.fs_lock:
            ps.commit(accepted, guard)
        for e in accepted:
            self.stats["wild" if e["kind"] == "wildcard" else "exact"] += 1
            n = len(e.get("superseded") or [])
            note = f" · replaces {n} narrower rule{'s' if n != 1 else ''}" if n else ""
            self.emit("block", e["value"], f"{e['category']}: {e['reason']}{note}",
                      conf=e["confidence"], sub=e["kind"], cat=e["category"])
        if not decisions:
            self.emit("system", "Nothing to block", "Gemini judged every candidate safe to leave alone")
        skip = set()
        for r in rejected:
            skip.update(r.get("undecided", ()))
        ps._DISABLED_SEEN.update(skip)  # not re-asked this run, retried if the category is enabled later
        now = time.time()
        for d in batch:
            if d in skip:
                continue
            decided[d] = now
        ps._save_json(ps.DECIDED_PATH, decided)
        self.stats["batches"] += 1

    def _live(self):
        ps = self.ps
        guard = self.guard = ps.Guard()
        guard.refresh(force=True)
        fam = ps.FamilyIndex()
        fam.refresh(force=True)
        decided = ps.load_decided()
        queue = {d for d in ps.load_disk_backlog() if ps.is_candidate(d, guard, decided)}
        self.emit("system", "Live hunter started",
                  f"Watching your Pi-hole log · aggression {self.aggression}"
                  + (f" · {len(queue)} backlogged" if queue else ""))
        if not fam.ok:
            self.emit("error", "Query history unavailable", "Wildcards will be downgraded to exact hosts")

        last_batch, next_api, backoff = time.time(), 0.0, 30
        f = open(ps.LOG_FILE, "r")
        f.seek(0, os.SEEK_END)
        inode = os.fstat(f.fileno()).st_ino
        try:
            while not self.stop.is_set():
                now = time.time()
                guard.refresh()
                with self.fs_lock:
                    ps.maybe_run_gravity()
                self.queue_len = len(queue)

                if queue and now >= next_api and (now - last_batch >= ps.BATCH_WAIT or len(queue) >= ps.BATCH_SIZE):
                    stale = [d for d in list(queue)[:ps.BATCH_SIZE] if not ps.is_candidate(d, guard, decided)]
                    queue.difference_update(stale)
                    chunk = list(queue)[:ps.BATCH_SIZE]
                    if chunk:
                        try:
                            self._process(chunk, guard, fam, decided)
                            queue.difference_update(chunk)
                            ps.save_disk_backlog(queue)
                            last_batch, backoff = now, 30
                        except Exception as e:
                            self.stats["errors"] += 1
                            self.last_error = str(e)
                            self.emit("error", "Gemini API error — will retry", f"{str(e)[:160]} · backing off {backoff}s")
                            ps.save_disk_backlog(queue)
                            next_api = now + backoff
                            backoff = min(backoff * 2, 300)

                line = f.readline()
                if not line:
                    try:  # follow log rotation / truncation
                        st = os.stat(ps.LOG_FILE)
                        if st.st_ino != inode or st.st_size < f.tell():
                            f.close()
                            f = open(ps.LOG_FILE, "r")
                            inode = os.fstat(f.fileno()).st_ino
                    except OSError:
                        pass
                    self.stop.wait(0.1)
                    continue

                if "reply " in line and " is " in line:
                    try:
                        parts = line.split()
                        domain = parts[parts.index("reply") + 1].lower().rstrip(".")
                    except (ValueError, IndexError):
                        continue
                    if domain not in queue and ps.is_candidate(domain, guard, decided):
                        queue.add(domain)
                        self.stats["seen"] += 1
                        ps.save_disk_backlog(queue)
                        self.emit("queue", domain, "Queued for evaluation")
        finally:
            f.close()
            ps.save_disk_backlog(queue)
            self.emit("system", "Live hunter stopped", "")

    def _audit(self):
        ps = self.ps
        if not os.path.exists(ps.DB_PATH):
            raise RuntimeError(f"Pi-hole database not found at {ps.DB_PATH}")
        guard = self.guard = ps.Guard()
        guard.refresh(force=True)
        fam = ps.FamilyIndex()
        fam.refresh(force=True)
        decided = ps.load_decided()
        self.audit = {"done": 0, "total": 0, "phase": "collecting"}
        before = dict(self.stats)
        self.emit("system", "History scan started", "Reviewing the last 30 days of allowed lookups")
        conn = sqlite3.connect(ps.DB_PATH, timeout=15)
        try:
            cur = conn.cursor()
            since = int(time.time()) - 30 * 86400
            try:
                cur.execute("SELECT DISTINCT domain FROM queries WHERE status IN (2, 3) AND timestamp > ?", (since,))
            except sqlite3.OperationalError:
                cur.execute("SELECT DISTINCT domain FROM queries WHERE status IN (2, 3)")
            rows = cur.fetchall()
        finally:
            conn.close()
        cands = sorted({(r[0] or "").lower() for r in rows})
        cands = [d for d in cands if ps.is_candidate(d, guard, decided)]
        self.audit = {"done": 0, "total": len(cands), "phase": "reviewing"}
        self.emit("system", f"{len(cands)} candidates to review", "")
        for i in range(0, len(cands), ps.BATCH_SIZE):
            if self.stop.is_set():
                break
            chunk = cands[i:i + ps.BATCH_SIZE]
            try:
                self._process(chunk, guard, fam, decided)
            except Exception as e:
                self.stats["errors"] += 1
                self.last_error = str(e)
                self.emit("error", "Gemini API error — scan stopped", str(e)[:200])
                break
            self.audit["done"] = min(len(cands), i + len(chunk))
            if self.stop.wait(2):  # gentle on free-tier rate limits
                break
        added = (self.stats["wild"] - before["wild"]) + (self.stats["exact"] - before["exact"])
        self.last_audit = {"ts": time.time(), "reviewed": self.audit["done"], "total": self.audit["total"],
                           "added": added, "refused": self.stats["rejected"] - before["rejected"]}
        self.emit("system", "History scan finished",
                  f"{self.audit['done']} of {self.audit['total']} reviewed · {added} rule{'s' if added != 1 else ''} added")


def read_rules(ps):
    """Active rules, joined with the confidence/reason Pi-Scout logged when it added them."""
    meta = {}
    try:
        size = os.path.getsize(ps.DECISION_LOG)
        with open(ps.DECISION_LOG, "rb") as f:
            f.seek(max(0, size - 2_000_000))
            lines = f.read().decode("utf-8", "ignore").splitlines()
        for line in (lines[1:] if size > 2_000_000 else lines):
            try:
                j = json.loads(line)
            except ValueError:
                continue
            if j.get("applied") and j.get("kind") in ("wildcard", "exact"):
                meta[j["value"]] = j
    except OSError:
        pass
    cat_of = {ps.category_path(c): c for c in ps.CATEGORIES}
    rules = []
    for path, (wild, exact) in ps.load_blocks_by_file().items():
        cat = cat_of[path]
        for kind, items in (("wildcard", wild), ("exact", exact)):
            for v in items:
                m = meta.get(v) or {}
                rules.append({"value": v, "kind": kind, "cat": cat, "confidence": m.get("confidence"),
                              "category": m.get("category"), "reason": m.get("reason"), "ts": m.get("ts")})
    rules.sort(key=lambda r: (r["ts"] is None, -(r["ts"] or 0), r["value"]))
    return rules


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "PiScoutUI/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") or ctype == "application/json" else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def _authed(self):
        if NO_AUTH:
            return True
        v = SimpleCookie(self.headers.get("Cookie", "")).get("ps_token")
        return bool(v) and hmac.compare_digest(v.value.encode(), TOKEN.encode())

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        tok = (qs.get("token") or [""])[0]
        if tok and hmac.compare_digest(tok.encode(), TOKEN.encode()):
            return self._send(302, b"", "text/plain", {
                "Location": "/", "Set-Cookie": f"ps_token={TOKEN}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000"})
        if u.path == "/favicon.ico":
            return self._send(204, b"", "text/plain")
        if not self._authed():
            if u.path.startswith("/api/"):
                return self._json({"error": "unauthorized"}, 401)
            return self._send(401, LOGIN, "text/html")
        if u.path == "/":
            return self._send(200, PAGE, "text/html")
        if u.path == "/api/state":
            since = int((qs.get("since") or ["0"])[0] or 0)
            return self._json(ENGINE.state(since))
        if u.path == "/api/rules":
            rules = read_rules(ENGINE.ps)
            return self._json({"total": len(rules), "rules": rules[:3000]})
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._authed():
            return self._json({"error": "unauthorized"}, 401)
        if self.headers.get("X-PiScout") != "1":  # forces a CORS preflight for cross-site pages
            return self._json({"error": "forbidden"}, 403)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}") if n <= 10_000 else None
        except (ValueError, TypeError):
            body = None
        if not isinstance(body, dict):
            return self._json({"error": "bad request"}, 400)
        path = urlparse(self.path).path
        try:
            if path == "/api/control":
                ENGINE.set_options(body.get("aggression"), body.get("categories"))
                act = body.get("action")
                if act == "start":
                    ok, msg = ENGINE.start("live")
                    if not ok:
                        return self._json({"error": msg}, 400)
                elif act == "stop":
                    ENGINE.request_stop()
                return self._json({"ok": True})
            if path == "/api/audit":
                ok, msg = ENGINE.start("audit")
                return self._json({"ok": True} if ok else {"error": msg}, 200 if ok else 400)
            if path == "/api/reset":
                cats = body.get("categories")
                if cats == "all":
                    cats = list(ENGINE.ps.CATEGORIES)
                if not isinstance(cats, list):
                    return self._json({"error": 'categories must be a list or "all"'}, 400)
                try:
                    ok, res = ENGINE.reset(cats)
                except Busy as e:
                    return self._json({"error": str(e)}, 409)
                return self._json({"ok": True, **res} if ok else {"error": res}, 200 if ok else 400)
            if path == "/api/allow":
                ok, msg = ENGINE.allow(body.get("domain"))
                return self._json({"ok": True} if ok else {"error": msg}, 200 if ok else 400)
        except (TypeError, ValueError) as e:
            return self._json({"error": str(e)}, 400)
        self._json({"error": "not found"}, 404)


LOGIN = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Pi-Scout</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#090d15;color:#e7edf8;font:15px system-ui}form{background:#131b2d;border:1px solid #1e2a40;border-radius:14px;padding:26px;width:min(92vw,340px)}h1{margin:0 0 4px;font-size:18px}p{margin:0 0 16px;color:#93a1b8;font-size:13px}input,button{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a3956;background:#0c1220;color:inherit;font:inherit;margin-bottom:10px}button{background:linear-gradient(135deg,#6366f1,#22d3ee);border:0;color:#fff;font-weight:600;cursor:pointer}</style><form method=get action=/><h1>Pi-Scout</h1><p>Enter the access token printed in the terminal.</p><input name=token type=password placeholder="Access token" autofocus><button>Open dashboard</button></form>"""

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#080c14">
<title>Pi-Scout</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%236366f1'/%3E%3Cpath d='M12 4l7 2.6v5.4c0 4.2-3 6.9-7 7.8-4-.9-7-3.6-7-7.8V6.6z' fill='none' stroke='white' stroke-width='1.8'/%3E%3C/svg%3E">
<style>
*{box-sizing:border-box}
:root{--bg:#080c14;--line:#1d283d;--line2:#2a3956;--txt:#e8eef9;--mut:#97a5bd;--dim:#62718b;--b1:#6366f1;--b2:#22d3ee;--pad:16px;
/* what happened (events) */
--ok:#34d399;--okb:rgba(52,211,153,.11);--warn:#facc15;--warnb:rgba(250,204,21,.10);--bad:#fb7185;--badb:rgba(251,113,133,.12);
--info:#60a5fa;--infob:rgba(96,165,250,.11);--rst:#fb923c;--rstb:rgba(251,146,60,.12);--mute:#7d8aa3;
/* which list (categories) */
--ads:#a78bfa;--adsb:rgba(167,139,250,.17);--trk:#22d3ee;--trkb:rgba(34,211,238,.15);--adl:#f472b6;--adlb:rgba(244,114,182,.16);--oth:#94a3b8;--othb:rgba(148,163,184,.15);
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
[hidden]{display:none!important}
html,body{margin:0}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--txt);min-height:100vh;-webkit-font-smoothing:antialiased;-webkit-text-size-adjust:100%;
background:radial-gradient(1100px 520px at 8% -8%,rgba(99,102,241,.22),transparent 60%),radial-gradient(900px 480px at 100% -4%,rgba(34,211,238,.12),transparent 55%),var(--bg)}
.wrap{max-width:1200px;margin:0 auto;padding:18px max(var(--pad),env(safe-area-inset-right)) calc(40px + env(safe-area-inset-bottom)) max(var(--pad),env(safe-area-inset-left))}
.c-ads{--cc:var(--ads);--ccb:var(--adsb)}.c-tracking{--cc:var(--trk);--ccb:var(--trkb)}.c-adult{--cc:var(--adl);--ccb:var(--adlb)}.c-other{--cc:var(--oth);--ccb:var(--othb)}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.logo{width:40px;height:40px;flex:none;border-radius:12px;background:linear-gradient(135deg,var(--b1),var(--b2));display:grid;place-items:center;box-shadow:0 8px 24px -8px rgba(99,102,241,.8)}
h1{font-size:19px;margin:0;letter-spacing:-.01em}
.brand p{margin:0;color:var(--mut);font-size:12px}
.topr{display:flex;align-items:center;gap:10px}
.card{background:linear-gradient(180deg,#131b2d,#0f1626);border:1px solid var(--line);border-radius:14px;box-shadow:0 14px 34px -22px #000}
.pill{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:999px;border:1px solid var(--line2);font-size:12px;background:rgba(15,22,38,.7);white-space:nowrap}
.pill b{font-weight:600}
.dot{width:8px;height:8px;border-radius:50%;background:var(--dim);display:inline-block}
.pill.live{border-color:rgba(52,211,153,.4);color:var(--ok)}.pill.live .dot{background:var(--ok);animation:pulse 1.8s infinite}
.pill.audit{border-color:rgba(96,165,250,.4);color:var(--info)}.pill.audit .dot{background:var(--info);animation:pulse 1.2s infinite}
.pill.stop{border-color:rgba(250,204,21,.4);color:var(--warn)}.pill.stop .dot{background:var(--warn)}
@keyframes pulse{0%{box-shadow:0 0 0 0 currentColor}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
.btn{font:inherit;font-weight:600;border:1px solid var(--line2);background:#16203a;color:var(--txt);padding:8px 16px;border-radius:10px;cursor:pointer;transition:.15s}
.btn:hover{border-color:#41547c;background:#1b2745}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.primary{border:0;color:#fff;background:linear-gradient(135deg,var(--b1),#4f8ff0 60%,var(--b2));box-shadow:0 8px 22px -10px rgba(99,102,241,.9)}
.btn.primary:hover{filter:brightness(1.1)}
.btn.danger,.btn.armed,.ib.armed{border:0;color:#fff;background:linear-gradient(135deg,#e11d48,#fb7185)}
.btn.ghost{background:transparent}
.btn.small{padding:6px 12px;font-size:13px}
.btn.dl{color:var(--bad);border-color:rgba(251,113,133,.35)}.btn.dl:hover{background:var(--badb);border-color:rgba(251,113,133,.6)}
:focus-visible{outline:2px solid var(--b2);outline-offset:2px}
.banner{background:var(--badb);border:1px solid rgba(251,113,133,.4);color:var(--bad);padding:8px 12px;border-radius:10px;margin-bottom:12px;font-size:13px}
.ctrl{display:grid;grid-template-columns:1.5fr 1fr;gap:26px;padding:16px 18px;margin-bottom:12px;align-items:center}
.rowb{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.rowb label{font-weight:600}
.aval{font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;background:rgba(129,140,248,.15);color:#a5b4fc}
input[type=range]{-webkit-appearance:none;appearance:none;width:100%;height:6px;border-radius:99px;outline-offset:6px;margin:6px 0;
background:linear-gradient(90deg,var(--b1),var(--b2)) 0/var(--p,50%) 100% no-repeat,#1c2740;cursor:pointer;touch-action:pan-y}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:20px;height:20px;border-radius:50%;background:#fff;border:3px solid var(--b1);box-shadow:0 2px 10px rgba(0,0,0,.5)}
input[type=range]::-moz-range-thumb{width:14px;height:14px;border-radius:50%;background:#fff;border:3px solid var(--b1)}
.ticks{display:flex;justify-content:space-between;color:var(--dim);font-size:11px;margin:4px 0 10px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-size:12px;padding:3px 9px;border-radius:8px;background:rgba(148,163,184,.11);color:var(--mut);border:1px solid var(--line);font-family:var(--mono)}
.scan{display:flex;flex-direction:column;gap:9px}
.scanh{display:flex;flex-direction:column;gap:3px}.scanh b{font-weight:600}
.scand{color:var(--mut);font-size:12.5px;line-height:1.45}
.scanrow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.scanst{color:var(--mut);font-size:12.5px}
.sw{display:flex;align-items:center;gap:12px;cursor:pointer;position:relative;min-width:0}
.sw input{position:absolute;opacity:0;pointer-events:none}
.knob{width:40px;height:22px;border-radius:99px;background:#26324d;position:relative;flex:none;transition:.2s}
.knob:after{content:"";position:absolute;left:3px;top:3px;width:16px;height:16px;border-radius:50%;background:#fff;transition:.2s}
.sw input:checked+.knob{background:var(--ok)}.sw input:checked+.knob:after{left:21px}
.sw input:focus-visible+.knob{outline:2px solid var(--b2);outline-offset:2px}
.swt{display:flex;flex-direction:column;line-height:1.25;min-width:0}.swt small{color:var(--mut);font-size:12px}
.prog{height:6px;border-radius:9px;background:#1c2740;margin-top:2px;overflow:hidden}.prog i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--info),var(--b2));transition:width .4s}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:12px}
.kpi{padding:12px 14px;border-radius:14px;border:1px solid var(--line);background:linear-gradient(180deg,#131b2d,#0f1626);display:flex;flex-direction:column;gap:1px;position:relative;overflow:hidden}
.kpi:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c,var(--b1))}
.kpi span{color:var(--mut);font-size:12px}.kpi b{font-size:26px;letter-spacing:-.02em;font-variant-numeric:tabular-nums;line-height:1.15}.kpi small{color:var(--dim);font-size:12px}
.grid{display:grid;grid-template-columns:1fr 330px;gap:12px;align-items:start}
.side{display:flex;flex-direction:column;gap:12px;min-width:0}
.main{min-width:0}
.sc{padding:14px 16px}.sc h3{margin:0 0 10px;font-size:13px;font-weight:600}.sc h3 small{color:var(--dim);font-weight:400;margin-left:4px}
.tabs{display:flex;align-items:center;gap:4px;padding:8px 10px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tab{font:inherit;font-weight:600;background:none;border:0;color:var(--mut);padding:7px 12px;border-radius:9px;cursor:pointer}
.tab em{font-style:normal;font-size:11px;margin-left:5px;padding:1px 7px;border-radius:99px;background:rgba(148,163,184,.14)}
#tabFeed{background:var(--ok);color:#052e1f;font-weight:800}
.tab.on{background:#1a2540;color:var(--txt)}
.sp{flex:1}
.fl{display:flex;align-items:center;gap:4px;flex-wrap:wrap}
.fc{font:inherit;font-size:12px;background:none;border:1px solid transparent;color:var(--mut);padding:4px 10px;border-radius:99px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.fc.on{border-color:var(--line2);color:var(--txt);background:#16203a}
.fc[data-f=block]:before,.fc[data-f=reject]:before,.fc[data-f=system]:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--c)}
.fc[data-f=block]{--c:var(--ok)}.fc[data-f=reject]{--c:var(--warn)}.fc[data-f=system]{--c:var(--mute)}
.mini{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--mut);margin-left:6px;cursor:pointer}
.rtools{display:flex;gap:8px;align-items:center}
.search{font:inherit;background:#0c1220;border:1px solid var(--line2);color:var(--txt);border-radius:9px;padding:6px 10px;width:210px;max-width:100%}
select.search{width:auto;min-width:150px}
/* ---------- live feed: each kind of event has its own colour, tint and label ---------- */
.feed{max-height:600px;min-height:300px;overflow:auto;padding:6px 8px}
.ev{display:grid;grid-template-columns:32px 1fr auto;gap:10px;align-items:center;padding:9px 11px;margin:5px 0;border-radius:11px;border:1px solid rgba(255,255,255,.05);border-left:3px solid var(--c);background:linear-gradient(90deg,var(--cb),rgba(255,255,255,.015) 75%)}
.ev.new{animation:in .5s ease-out}
@keyframes in{from{opacity:0;transform:translateY(-6px);filter:brightness(1.6)}}
.ico{width:32px;height:32px;border-radius:9px;display:grid;place-items:center;color:var(--c);background:var(--cb)}
.k-block{--c:var(--ok);--cb:var(--okb)}.k-reject{--c:var(--warn);--cb:var(--warnb)}.k-error{--c:var(--bad);--cb:var(--badb)}
.k-allow{--c:var(--info);--cb:var(--infob)}.k-reset{--c:var(--rst);--cb:var(--rstb)}
.k-queue,.k-batch,.k-gravity,.k-system{--c:var(--mute);--cb:transparent}
.k-queue,.k-batch,.k-gravity,.k-system{padding:6px 11px;border-color:transparent;border-left-color:var(--line2);background:none}
.k-queue{opacity:.75}
.k-batch .ico,.k-gravity .ico,.k-system .ico,.k-queue .ico{background:rgba(148,163,184,.1);width:26px;height:26px}
.eb{min-width:0}.et{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.kl{font-size:10px;font-weight:800;letter-spacing:.07em;color:var(--c)}
.dm{font-family:var(--mono);font-size:13px;font-weight:600;overflow-wrap:anywhere}
.st{font-size:13.5px;font-weight:600}
.k-queue .dm{font-weight:500;color:var(--mut)}
.ed{color:var(--mut);font-size:12.5px;overflow-wrap:anywhere}
.em{display:flex;flex-direction:column;align-items:flex-end;gap:2px;font-size:11px;color:var(--dim);font-variant-numeric:tabular-nums}
.conf{color:var(--c);font-weight:800;font-size:12.5px}
.tag{font-size:10px;font-weight:800;letter-spacing:.05em;padding:1px 6px;border-radius:6px;border:1px solid transparent}
.t-w{background:var(--ccb,rgba(148,163,184,.15));color:var(--cc,#e8eef9);border-color:var(--cc,var(--line2))}
.t-e{background:rgba(148,163,184,.1);color:var(--mut)}
.pillc{font-size:10px;font-weight:800;padding:1px 8px;border-radius:99px;letter-spacing:.04em;text-transform:uppercase;background:var(--ccb);color:var(--cc)}
.pc-ads{--cc:var(--ads);--ccb:var(--adsb)}.pc-tracking{--cc:var(--trk);--ccb:var(--trkb)}.pc-adult{--cc:var(--adl);--ccb:var(--adlb)}.pc-other{--cc:var(--oth);--ccb:var(--othb)}
.empty{display:grid;place-items:center;text-align:center;gap:8px;padding:70px 20px;color:var(--mut)}
.radar{width:54px;height:54px;border-radius:50%;border:2px solid var(--line2);position:relative;overflow:hidden}
.radar:after{content:"";position:absolute;inset:0;background:conic-gradient(from 0deg,rgba(34,211,238,.5),transparent 40%);animation:spin 2.4s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
/* ---------- rules: colour = list, outlined badge + tint = wildcard, confidence has traffic-light colours ---------- */
.tw{overflow:auto;max-height:640px}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{position:sticky;top:0;z-index:1;background:#111a2c;text-align:left;color:var(--mut);font-weight:600;font-size:11px;letter-spacing:.04em;text-transform:uppercase;padding:9px 12px;border-bottom:1px solid var(--line)}
.tbl td{padding:9px 12px;border-bottom:1px solid rgba(30,42,64,.6);vertical-align:middle}
.tbl td:first-child{box-shadow:inset 3px 0 0 var(--cc)}
.tbl tr.w td{background:var(--ccb);background:color-mix(in srgb,var(--cc) 9%,transparent)}
.tbl tr:hover td{background:rgba(255,255,255,.035)}
.tbl .dm{font-size:12.5px;white-space:nowrap}.tbl .dm b{font-weight:700}
.tbl tr.w .dm b{color:var(--cc)}
.sub{font-style:normal;color:var(--mut);font-weight:500}.syn{font-style:normal;color:var(--dim);font-weight:500}
.rs{color:var(--mut);max-width:300px}
.cf{font-weight:800;font-variant-numeric:tabular-nums}.cf-hi{color:var(--ok)}.cf-mid{color:var(--warn)}.cf-lo{color:var(--rst)}
.note{padding:10px 14px;color:var(--dim);font-size:12px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.inl{display:flex;gap:8px}
.inl input{flex:1;min-width:0;font:inherit;font-family:var(--mono);font-size:13px;background:#0c1220;border:1px solid var(--line2);color:var(--txt);border-radius:9px;padding:7px 10px}
.hint{color:var(--dim);font-size:12px;margin:8px 0 10px}
/* ---------- categories ---------- */
.cats{display:flex;flex-direction:column;gap:2px;margin:0 -6px}
.crow{display:grid;grid-template-columns:1fr auto auto;align-items:center;gap:8px;padding:6px 6px;border-radius:10px}
.crow:hover{background:rgba(255,255,255,.03)}
.crow .sw{gap:10px}.crow .knob{width:34px;height:19px}.crow .knob:after{width:13px;height:13px;top:3px}
.crow .sw input:checked+.knob{background:var(--cc)}.crow .sw input:checked+.knob:after{left:18px}
.crow .swt b{font-weight:600;font-size:13px;display:flex;align-items:center;gap:7px}
.crow .swt b:before{content:"";width:9px;height:9px;border-radius:3px;background:var(--cc)}
.crow .swt small{font-family:var(--mono);font-size:11px;color:var(--dim);padding-left:16px}
.cnt{font-style:normal;font-weight:800;font-variant-numeric:tabular-nums;color:var(--cc);font-size:14px;min-width:22px;text-align:right}
.ib{display:grid;place-items:center;min-width:32px;height:32px;border-radius:9px;border:1px solid var(--line2);background:transparent;color:var(--mut);cursor:pointer;transition:.15s;font:inherit;font-size:12px;font-weight:700;padding:0}
.ib:hover:not(:disabled){color:var(--bad);border-color:rgba(251,113,133,.5);background:var(--badb)}
.ib:disabled{opacity:.35;cursor:not-allowed}
.ib.armed{width:auto;padding:0 10px}
.cfoot{margin:8px 6px 0;padding-top:12px;border-top:1px solid var(--line)}
.cfoot .btn{width:100%}.cfoot .hint{margin:8px 0 0}
#chart{width:100%;height:64px;display:block}
.legend{display:flex;gap:14px;color:var(--mut);font-size:12px;margin-top:8px}.lg{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px}.lg.ok{background:var(--ok)}.lg.rj{background:var(--warn)}
.kv{margin:0;display:grid;grid-template-columns:auto 1fr;gap:7px 12px;font-size:13px}.kv dt{color:var(--mut)}.kv dd{margin:0;text-align:right;font-variant-numeric:tabular-nums;min-width:0;overflow-wrap:anywhere}
.good{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
#toast{position:fixed;right:max(16px,env(safe-area-inset-right));bottom:max(16px,env(safe-area-inset-bottom));display:flex;flex-direction:column;gap:8px;z-index:9}
.toast{background:#16203a;border:1px solid var(--line2);padding:10px 14px;border-radius:10px;box-shadow:0 12px 30px -10px #000;animation:in .3s;max-width:min(340px,calc(100vw - 32px));font-size:13px}
.toast.err{border-color:rgba(251,113,133,.5);color:var(--bad)}.toast.ok{border-color:rgba(52,211,153,.4)}
/* ---------- tablets and phones ---------- */
@media(max-width:980px){
 .grid{grid-template-columns:1fr}
 .ctrl{grid-template-columns:1fr;gap:18px}
 .side{display:contents}
 #catCard{order:1}.main{order:2}.side .sc:not(#catCard){order:3}
}
@media(max-width:820px){
 .kpis{display:flex;overflow-x:auto;scroll-snap-type:x proximity;gap:10px;margin:0 calc(var(--pad)*-1) 12px;padding:0 var(--pad) 4px;-webkit-overflow-scrolling:touch;scrollbar-width:none}
 .kpis::-webkit-scrollbar{display:none}
 .kpi{flex:0 0 152px;scroll-snap-align:start}
}
@media(max-width:760px){
 .tbl thead{display:none}
 .tbl,.tbl tbody{display:block}
 .tbl tr{display:flex;flex-wrap:wrap;align-items:center;gap:7px 8px;padding:12px 12px 12px 14px;border-bottom:1px solid var(--line);border-left:3px solid var(--cc)}
 .tbl td{display:block;padding:0;border:0;box-shadow:none!important;background:none!important}
 .tbl tr.w{background:var(--ccb);background:color-mix(in srgb,var(--cc) 9%,transparent)}
 .tbl .c-rule{order:1;flex:1 1 100%;min-width:0}
 .tbl .c-type{order:2}.tbl .c-list{order:3}.tbl .c-conf{order:4}.tbl .c-act{order:5;margin-left:auto}
 .tbl .c-why{order:6;flex-basis:100%;max-width:none;font-size:12.5px}
 .tbl .dm{white-space:normal;overflow-wrap:break-word}
 .tw{max-height:none;overflow:visible}
 .feed{max-height:none;min-height:200px}
 .tab{flex:1;text-align:center}
 .rtools,.fl{flex:1 1 100%}
 .rtools .search{flex:1;min-width:0}
 .fl{justify-content:space-between}
}
@media(max-width:560px){
 :root{--pad:12px}
 h1{font-size:17px}.brand p{display:none}
 .logo{width:36px;height:36px}
 .card.ctrl{padding:14px}
 .ev{grid-template-columns:28px 1fr;gap:8px;padding:9px 10px}
 .ev .em{grid-column:2;flex-direction:row;align-items:center;gap:8px}
 .ico{width:28px;height:28px}
 input,select{font-size:16px!important}
 .kpi b{font-size:23px}
}
@media(pointer:coarse){
 .btn{min-height:42px}.btn.small{min-height:38px}
 .tab{min-height:42px}.fc{min-height:36px;padding:6px 12px}
 .ib{min-width:40px;height:40px}
 .search,.inl input{min-height:42px}
 .knob{width:46px;height:26px}.knob:after{width:20px;height:20px}.sw input:checked+.knob:after{left:23px}
 .crow .knob{width:42px;height:24px}.crow .knob:after{width:18px;height:18px}.crow .sw input:checked+.knob:after{left:21px}
 input[type=range]{height:8px;margin:12px 0}
 input[type=range]::-webkit-slider-thumb{width:28px;height:28px}
 input[type=range]::-moz-range-thumb{width:22px;height:22px}
}
@media(prefers-reduced-motion:reduce){*{animation:none!important}}
</style></head>
<body><div class="wrap">
<header class="top">
 <div class="brand"><div class="logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><circle cx="12" cy="11" r="2.4"/><path d="M12 11l3-3"/></svg></div>
 <div><h1>Pi-Scout</h1><p>AI vanguard for Pi-hole</p></div></div>
 <div class="topr"><span class="pill" id="pill"><i class="dot"></i><b id="pillTxt">Idle</b></span><button class="btn primary" id="runBtn">Start</button></div>
</header>
<div class="banner" id="offline" hidden>Connection lost — retrying…</div>

<section class="card ctrl">
 <div>
  <div class="rowb"><label for="agg">Wildcard aggression</label><span class="aval" id="aggVal">7 · Balanced</span></div>
  <input type="range" min="1" max="10" step="1" value="7" id="agg" aria-describedby="thW">
  <div class="ticks"><span>Conservative</span><span>Balanced</span><span>Aggressive</span></div>
  <div class="chips"><span class="chip" id="thW">Wildcards ≥ 86%</span><span class="chip" id="thE">Exact hosts ≥ 81%</span></div>
 </div>
 <div class="scan">
  <div class="scanh"><b>History scan</b><span class="scand">A one-time review of the last 30 days of lookups your lists let through, to find ad, tracker and adult domains they missed. It runs once and stops.</span></div>
  <div class="scanrow"><button class="btn small" id="auditBtn">Scan last 30 days</button><span class="scanst" id="scanSt"></span></div>
  <div class="prog" id="prog" hidden><i id="progBar"></i></div>
 </div>
</section>

<section class="kpis">
 <div class="kpi" style="--c:var(--b1)"><span>Active rules</span><b id="kRules">0</b><small id="kRulesS">0 wildcard · 0 exact</small></div>
 <div class="kpi" style="--c:var(--ok)"><span>Blocked this session</span><b id="kBlocked">0</b><small id="kBlockedS">0 wildcard · 0 exact</small></div>
 <div class="kpi" style="--c:var(--warn)"><span>Refused by guards</span><b id="kRej">0</b><small>kept off your blocklist</small></div>
 <div class="kpi" style="--c:var(--info)"><span>Queue</span><b id="kQueue">0</b><small id="kSeen">0 seen this session</small></div>
 <div class="kpi" style="--c:var(--b2)"><span>Gemini batches</span><b id="kBatch">0</b><small id="kErr">0 errors</small></div>
</section>

<main class="grid">
 <section class="card main">
  <div class="tabs">
   <button class="tab on" data-t="rules">Rules <em id="tabRules">0</em></button><button class="tab" data-t="feed">Live feed <em id="tabFeed" hidden>0</em></button><div class="sp"></div>
   <div class="fl" id="feedTools" hidden><button class="fc on" data-f="all">All</button><button class="fc" data-f="block">Blocks</button><button class="fc" data-f="reject">Refused</button><button class="fc" data-f="system">System</button><label class="mini"><input type="checkbox" id="cand">Candidates</label></div>
   <div class="rtools" id="ruleTools"><select class="search" id="catSel" aria-label="Filter by category"><option value="">All categories</option><option value="ads">Ads</option><option value="tracking">Tracking</option><option value="adult">Adult</option><option value="other">Other</option></select>
   <input class="search" id="q" placeholder="Search rules…" aria-label="Search rules"></div>
  </div>
  <div id="feed" class="feed" hidden></div>
  <div id="rulesBox"><div class="tw"><table class="tbl"><thead><tr><th>Rule</th><th>Type</th><th>Conf.</th><th>List</th><th>Reason</th><th></th></tr></thead><tbody id="rulesBody"></tbody></table></div><div class="note" id="rulesNote"></div></div>
 </section>
 <aside class="side">
  <div class="card sc" id="catCard"><h3>Categories <small>one list file each</small></h3><div id="cats" class="cats"></div></div>
  <div class="card sc"><h3>Activity <small>last hour</small></h3><svg id="chart" viewBox="0 0 240 60" preserveAspectRatio="none" role="img" aria-label="Blocks and refusals per minute over the last hour"></svg>
   <div class="legend"><span><i class="lg ok"></i>Blocked</span><span><i class="lg rj"></i>Refused</span></div></div>
  <div class="card sc"><h3>Allow a domain</h3>
   <form id="allowForm" class="inl"><input id="allowIn" placeholder="app.example.com" autocomplete="off" autocapitalize="none" spellcheck="false" aria-label="Domain to allow"><button class="btn small">Allow</button></form>
   <p class="hint">Unblocks it now and never blocks it, or anything under it, again.</p>
   <div class="chips" id="never"></div></div>
  <div class="card sc"><h3>System</h3><dl class="kv" id="sys"></dl></div>
 </aside>
</main>
</div><div id="toast" aria-live="polite"></div>
<script>
const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const svg=p=>`<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const SH='<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>';
const TRASH='<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 002 2h6a2 2 0 002-2l1-12M9 7V4h6v3"/>';
const ICON={block:svg(SH+'<path d="M9 12l2 2 4-4"/>'),reject:svg(SH+'<path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/>'),
 queue:svg('<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/>'),
 batch:svg('<path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/>'),
 gravity:svg('<path d="M20 11a8 8 0 10-2.3 5.7"/><path d="M20 4v7h-7"/>'),
 error:svg('<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17v.5"/>'),
 allow:svg('<path d="M5 12.5l4.5 4.5L19 7.5"/>'),reset:svg(TRASH),
 system:svg('<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8v.5"/>')};
const LABEL={block:'BLOCKED',reject:'REFUSED',queue:'QUEUED',batch:'GEMINI',gravity:'GRAVITY',error:'ERROR',allow:'ALLOWED',reset:'CLEARED',system:'INFO'};
const DOMAIN_KINDS=['block','reject','queue','allow'],SYS_KINDS=['system','batch','gravity','error','allow','reset'];
const CATL={ads:'Ads',tracking:'Tracking',adult:'Adult',other:'Other'};
const S={cat:'',catSig:'',since:0,events:[],filter:'all',cand:false,tab:'rules',unseen:0,rulesSig:'',st:null,drag:false,fresh:new Set(),rules:[],q:'',limit:50};
const fmtTime=t=>new Date(t*1000).toLocaleTimeString([], {hour12:false});
const ago=t=>{if(!t)return'—';const s=Math.max(0,Date.now()/1000-t);return s<90?'just now':s<5400?Math.round(s/60)+'m ago':s<172800?Math.round(s/3600)+'h ago':Math.round(s/86400)+'d ago'};
const dur=s=>{s=Math.max(0,Math.floor(s));const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h?`${h}h ${m}m`:m?`${m}m ${s%60}s`:`${s}s`};
function toast(msg,kind){const d=document.createElement('div');d.className='toast '+(kind||'');d.textContent=msg;$('#toast').appendChild(d);setTimeout(()=>d.remove(),4200)}
async function api(path,body){
 const o=body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-PiScout':'1'},body:JSON.stringify(body)};
 const r=await fetch(path,o); if(r.status===401){location.reload();throw new Error('unauthorized')}
 const j=await r.json().catch(()=>({})); if(!r.ok)throw new Error(j.error||r.statusText); return j}
const modeName=a=>a<=3?'Conservative':a>=8?'Aggressive':'Balanced';
const th=a=>[Math.max(85,100-2*a),Math.max(75,95-2*a)];
function armed(btn,label,run){  /* two-step confirm: first tap arms the button, second tap runs it */
 if(btn.dataset.armed){clearTimeout(btn._t);delete btn.dataset.armed;return run()}
 btn.dataset.armed=1;btn._h=btn.innerHTML;btn.innerHTML=label;btn.classList.add('armed');
 btn._t=setTimeout(()=>{if(!btn.isConnected)return;delete btn.dataset.armed;btn.innerHTML=btn._h;btn.classList.remove('armed')},3500)}

function renderTop(s){
 const p=$('#pill'),run=$('#runBtn');let cls='',txt='Idle';
 if(s.stopping){cls='stop';txt='Stopping…'}
 else if(s.mode==='clearing'){cls='stop';txt='Clearing lists…'}
 else if(s.mode==='live'){cls='live';txt='Live'}
 else if(s.mode==='audit'){cls='audit';txt='Scanning history'}
 p.className='pill '+cls;$('#pillTxt').textContent=txt;
 run.disabled=s.stopping||s.mode==='clearing';
 if(s.mode==='clearing'){run.textContent='Clearing…';run.className='btn'}
 else if(s.mode==='idle'){run.textContent='Start';run.className='btn primary'}
 else{run.textContent=s.stopping?'Stopping…':(s.mode==='audit'?'Stop scan':'Stop');run.className='btn danger'}
 renderScan(s)}
function renderScan(s){
 const b=$('#auditBtn'),st=$('#scanSt'),pr=$('#prog'),a=s.audit;
 if(s.mode==='audit'){
  b.textContent=s.stopping?'Cancelling…':'Cancel scan';b.className='btn small danger';b.disabled=s.stopping;pr.hidden=false;
  const col=a.phase==='collecting'||!a.total;
  $('#progBar').style.width=(col?4:Math.max(4,Math.round(100*a.done/a.total)))+'%';
  st.textContent=col?'Collecting domains from your history…':`Reviewing ${a.done} of ${a.total} domains…`;
 }else{
  pr.hidden=true;b.textContent='Scan last 30 days';b.className='btn small';b.disabled=s.mode!=='idle';
  const la=s.last_audit;
  st.textContent=s.mode==='clearing'?'Clearing lists…':s.mode==='live'?'Stop live monitoring first; only one can run at a time.':la?`Last scan ${ago(la.ts)}: ${la.reviewed} reviewed · ${la.added} rule${la.added===1?'':'s'} added`:'Not run yet.';
 }}
function renderCtrl(s){if(!S.drag){const a=$('#agg');a.value=s.aggression;setAgg(s.aggression)}}
function setAgg(a){
 a=+a;$('#aggVal').textContent=a+' · '+modeName(a);const [w,e]=th(a);
 $('#thW').textContent='Wildcards ≥ '+w+'%';$('#thE').textContent='Exact hosts ≥ '+e+'%';
 $('#agg').style.setProperty('--p',((a-1)/9*100)+'%')}
function renderKpis(s){
 const r=s.rules,st=s.stats;
 $('#kRules').textContent=r.wild+r.exact;$('#kRulesS').textContent=r.wild+' wildcard · '+r.exact+' exact';
 $('#kBlocked').textContent=st.wild+st.exact;$('#kBlockedS').textContent=st.wild+' wildcard · '+st.exact+' exact';
 $('#kRej').textContent=st.rejected;$('#kQueue').textContent=s.queue;$('#kSeen').textContent=st.seen+' seen this session';
 $('#kBatch').textContent=st.batches;$('#kErr').textContent=st.errors+(st.errors===1?' error':' errors');
 $('#tabRules').textContent=r.wild+r.exact}
function renderTabs(s){
 const b=$('#tabFeed');b.hidden=!S.unseen;b.textContent=S.unseen>99?'99+':S.unseen;
 const sig=s.rules.wild+'/'+s.rules.exact;
 if(sig!==S.rulesSig){S.rulesSig=sig;if(S.tab==='rules')loadRules()}}
function renderCats(s,force){
 const sig=JSON.stringify(s.categories)+s.mode;if(sig===S.catSig&&!force)return;S.catSig=sig;let h='';const idle=s.mode==='idle';
 for(const c of Object.keys(s.categories)){const x=s.categories[c];
  h+=`<div class="crow c-${c}"><label class="sw"><input type="checkbox" data-cat="${c}"${x.enabled?' checked':''}><span class="knob"></span><span class="swt"><b>${CATL[c]}</b><small>${esc(x.file)}</small></span></label><em class="cnt">${x.count}</em><button class="ib" data-clear="${c}" title="${idle?'Clear all '+CATL[c]+' rules':'Stop Pi-Scout to clear lists'}" aria-label="Clear all ${CATL[c]} rules"${idle?'':' disabled'}>${svg(TRASH)}</button></div>`}
 h+=`<div class="cfoot"><button class="btn small dl" id="clearAll"${idle?'':' disabled'}>Clear all categories</button><p class="hint">${idle?'Clearing removes the rules (unblocked after the next gravity update) and makes Pi-Scout forget it already judged those domains. A backup copy is kept.':(s.mode==='clearing'?'Clearing lists…':'Clearing is only available while nothing is running. Stop live monitoring or the scan first.')}</p></div>`;
 $('#cats').innerHTML=h}
function renderSide(s){
 const sv=$('#chart'),max=Math.max(2,...s.series.map(x=>x[0]+x[1])),H=60;let h='';
 s.series.forEach((x,i)=>{const X=i*4;h+=`<rect x="${X}" y="${H-1.5}" width="3" height="1.5" rx="1" fill="#26324d"/>`;
  const hb=x[0]/max*(H-4),hr=x[1]/max*(H-4);
  if(hr)h+=`<rect x="${X}" y="${H-hr}" width="3" height="${hr}" rx="1" fill="#facc15"/>`;
  if(hb)h+=`<rect x="${X}" y="${H-hr-hb}" width="3" height="${hb}" rx="1" fill="#34d399"/>`});
 sv.innerHTML=h;
 const n=s.never;$('#never').innerHTML=n.length?n.slice(0,12).map(d=>`<span class="chip">${esc(d)}</span>`).join('')+(s.never_total>12?`<span class="chip">+${s.never_total-12} more</span>`:''):'<span class="hint" style="margin:0">Your never-block list is empty.</span>';
 const g=s.gravity,gtxt=g.pending?'<span class="warn">Pending</span>':(g.last?ago(g.last):'Idle');
 const rows=[['Status',s.stopping?'Stopping':s.mode==='idle'?'Idle':s.mode==='clearing'?'Clearing':s.mode==='audit'?'Scanning':'Running'],
  ['Uptime',`<span id="up">${s.started_at?dur(Date.now()/1000-s.started_at):'—'}</span>`],
  ['Model',`<span style="font-family:var(--mono);font-size:12px">${esc(s.model)}</span>`],
  ['Gravity',gtxt],['Gemini key',s.api_key?'<span class="good">Ready</span>':'<span class="bad">Missing</span>'],
  ['Protected',`${s.never_total} never-block · ${s.pihole_allow} Pi-hole allow`]];
 $('#sys').innerHTML=rows.map(r=>`<dt>${r[0]}</dt><dd>${r[1]}</dd>`).join('')}
function evHTML(e){
 const k=e.kind,dom=DOMAIN_KINDS.includes(k);let title=e.title,chips='';
 if(k==='block'||k==='reject'){
  const w=e.sub==='wildcard';title=w?'||'+e.title+'^':e.title;
  chips+=`<span class="tag ${w?'t-w':'t-e'} pc-${esc(e.cat||'other')}">${w?'WILDCARD':'EXACT'}</span>`;
  if(e.cat)chips+=`<span class="pillc pc-${esc(e.cat)}">${esc(CATL[e.cat]||e.cat)}</span>`}
 const conf=e.conf!=null?`<span class="conf">${Math.round(e.conf)}%</span>`:'';
 return `<div class="ev k-${k}${S.fresh.has(e.id)?' new':''}"><div class="ico">${ICON[k]||ICON.system}</div><div class="eb"><div class="et"><span class="kl">${LABEL[k]||'INFO'}</span><span class="${dom?'dm':'st'}">${esc(title)}</span>${chips}</div><div class="ed">${esc(e.detail)}</div></div><div class="em">${conf}<time>${fmtTime(e.ts)}</time></div></div>`}
function renderFeed(){
 const f=S.filter;
 const list=S.events.filter(e=>e.kind==='queue'?S.cand&&f==='all':f==='all'||(f==='block'&&e.kind==='block')||(f==='reject'&&e.kind==='reject')||(f==='system'&&SYS_KINDS.includes(e.kind)));
 $('#feed').innerHTML=list.length?list.map(evHTML).join(''):`<div class="empty"><div class="radar"></div><b>${S.st&&S.st.mode==='live'?'Listening for DNS traffic…':'Nothing here yet'}</b><span>${S.st&&S.st.mode==='live'?'Candidates appear as Pi-hole sees ad-tech domains.':'Press Start to begin watching your Pi-hole log.'}</span></div>`}
function ruleName(r){const v=r.value;
 if(r.kind==='wildcard')return `<span class="dm"><i class="syn">||</i><b>${esc(v)}</b><i class="syn">^</i></span>`;
 const p=v.split('.');let n=2;if(p.length>2&&p[p.length-1].length===2&&['co','com','org','net','gov','ac','ne','or'].includes(p[p.length-2]))n=3;
 const root=p.slice(-n).join('.'),sub=p.slice(0,-n).join('.');
 return `<span class="dm">${sub?`<i class="sub">${esc(sub)}.</i>`:''}<b>${esc(root)}</b></span>`}
function ruleRow(r){
 const w=r.kind==='wildcard',c=esc(r.cat);
 const cf=r.confidence==null?'<span class="cf">—</span>':`<span class="cf ${r.confidence>=95?'cf-hi':r.confidence>=85?'cf-mid':'cf-lo'}">${Math.round(r.confidence)}%</span>`;
 return `<tr class="c-${c}${w?' w':''}"><td class="c-rule">${ruleName(r)}<div class="ed">${esc(ago(r.ts))}</div></td><td class="c-type"><span class="tag ${w?'t-w':'t-e'}">${w?'WILDCARD':'EXACT'}</span></td><td class="c-conf">${cf}</td><td class="c-list"><span class="pillc pc-${c}">${esc(CATL[r.cat]||r.cat)}</span></td><td class="c-why rs">${esc(r.reason||'Added before the UI existed')}</td><td class="c-act"><button class="btn small ghost" data-allow="${esc(r.value)}">Allow</button></td></tr>`}
function renderRules(){
 const q=S.q.trim().toLowerCase(),base=S.cat?S.rules.filter(r=>r.cat===S.cat):S.rules,
  list=q?base.filter(r=>r.value.includes(q)||(r.reason||'').toLowerCase().includes(q)):base,shown=list.slice(0,S.limit),more=list.length-shown.length;
 $('#rulesBody').innerHTML=shown.map(ruleRow).join('');
 $('#rulesNote').innerHTML=list.length?`<span>${shown.length} of ${list.length} rule${list.length===1?'':'s'}</span>${more>0?`<button class="btn small ghost" id="more">Show ${Math.min(50,more)} more</button>`:''}`:esc(S.rules.length?'No rules match.':'No rules yet — they appear here as Pi-Scout finds ad, tracker and adult domains.')}
async function loadRules(){try{const j=await api('/api/rules');S.rules=j.rules;renderRules()}catch(e){}}
function ingest(s){
 const prev=S.since;S.fresh=new Set();
 s.events.forEach(e=>{if(e.id>S.since){S.events.unshift(e);if(prev){S.fresh.add(e.id);if(S.tab!=='feed'&&['block','reject','error'].includes(e.kind))S.unseen++}}});
 if(S.events.length>300)S.events.length=300;
 const changed=s.last_id!==S.since;S.since=s.last_id;return changed}
function render(s,changed){renderCats(s);renderTop(s);renderCtrl(s);renderKpis(s);renderSide(s);renderTabs(s);if(changed||S.feedDirty){renderFeed();S.feedDirty=false}}
async function poll(){
 try{const s=await api('/api/state?since='+S.since);S.st=s;const c=ingest(s);$('#offline').hidden=true;render(s,c||S.first===undefined);S.first=1}
 catch(e){if(e.message!=='unauthorized')$('#offline').hidden=false}
 setTimeout(poll,1500)}
setInterval(()=>{const s=S.st,u=$('#up');if(s&&s.started_at&&u)u.textContent=dur(Date.now()/1000-s.started_at)},1000);

$('#runBtn').onclick=async()=>{const s=S.st;if(!s)return;
 try{await api('/api/control',{action:s.mode==='idle'?'start':'stop',aggression:+$('#agg').value});
  if(s.mode==='idle')toast('Pi-Scout started','ok')}catch(e){toast(e.message,'err')}};
$('#auditBtn').onclick=async()=>{const s=S.st;if(!s)return;
 try{if(s.mode==='audit'){await api('/api/control',{action:'stop'})}
  else{await api('/api/control',{aggression:+$('#agg').value});await api('/api/audit',{});toast('Scanning the last 30 days…','ok')}}
 catch(e){toast(e.message,'err')}};
const agg=$('#agg');
agg.addEventListener('input',()=>{S.drag=true;setAgg(agg.value)});
agg.addEventListener('change',async()=>{try{await api('/api/control',{aggression:+agg.value})}catch(e){toast(e.message,'err')}S.drag=false});
$$('.tab').forEach(b=>b.onclick=()=>{S.tab=b.dataset.t;$$('.tab').forEach(x=>x.classList.toggle('on',x===b));
 const r=S.tab==='rules';$('#feed').hidden=r;$('#rulesBox').hidden=!r;$('#feedTools').hidden=r;$('#ruleTools').hidden=!r;
 if(r)loadRules();else{S.unseen=0;$('#tabFeed').hidden=true;S.fresh=new Set();renderFeed()}});
$$('.fc').forEach(b=>b.onclick=()=>{S.filter=b.dataset.f;$$('.fc').forEach(x=>x.classList.toggle('on',x===b));S.fresh=new Set();renderFeed()});
$('#cand').onchange=e=>{S.cand=e.target.checked;S.fresh=new Set();renderFeed()};
$('#q').oninput=e=>{S.q=e.target.value;S.limit=50;renderRules()};
$('#catSel').onchange=e=>{S.cat=e.target.value;S.limit=50;renderRules()};
$('#rulesNote').addEventListener('click',e=>{if(e.target.closest('#more')){S.limit+=50;renderRules()}});
setInterval(()=>{if(S.tab==='rules'&&!document.hidden)loadRules()},10000);
async function doAllow(d,btn){
 try{await api('/api/allow',{domain:d});toast('Allowed '+d,'ok');if(S.tab==='rules')loadRules()}catch(e){toast(e.message,'err');if(btn&&btn.isConnected){btn.textContent='Allow';btn.classList.remove('armed')}}}
$('#rulesBody').addEventListener('click',e=>{const b=e.target.closest('[data-allow]');if(b)armed(b,'Sure?',()=>doAllow(b.dataset.allow,b))});
$('#allowForm').onsubmit=async e=>{e.preventDefault();const i=$('#allowIn'),d=i.value.trim();if(!d)return;await doAllow(d);i.value=''};
$('#cats').addEventListener('change',async e=>{
 if(!e.target.matches('[data-cat]'))return;
 const on=[...$$('#cats [data-cat]')].filter(i=>i.checked).map(i=>i.dataset.cat);
 try{await api('/api/control',{categories:on})}catch(err){toast(err.message,'err');if(S.st)renderCats(S.st,true)}});
async function doReset(cats,label){
 try{const j=await api('/api/reset',{categories:cats});const n=Object.values(j.removed).reduce((a,x)=>a+x,0);
  toast(`Cleared ${label}: ${n} rule${n===1?'':'s'} removed · ${j.decided} judged and ${j.backlog} queued domains forgotten`,'ok');
  S.catSig='';S.limit=50;loadRules()}
 catch(err){toast(err.message,'err')}}
$('#cats').addEventListener('click',e=>{
 const b=e.target.closest('[data-clear]'),all=e.target.closest('#clearAll');
 if(b){const c=b.dataset.clear;armed(b,'Sure?',()=>doReset([c],CATL[c]))}
 else if(all)armed(all,'Tap again to clear everything',()=>doReset('all','all categories'))});
setAgg(7);poll();loadRules();
</script></body></html>
"""


# --------------------------------------------------------------------------
def main():
    global ENGINE, TOKEN, NO_AUTH
    ap = argparse.ArgumentParser(description="Pi-Scout UI — web dashboard for pi-scout.py")
    ap.add_argument("--host", default="0.0.0.0", help="Interface to listen on (default: all; use 127.0.0.1 for local only)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--key", "--gemini-key", dest="key", help="Gemini API key (else GEMINI_API_KEY or ~/.gemini_key)")
    ap.add_argument("--core", help="Path to pi-scout.py (default: next to this file, then /usr/local/bin)")
    ap.add_argument("--aggression", type=int, default=7, choices=range(1, 11), help="Default 7")
    grp = ap.add_argument_group("categories", "What to look for (default: --all). Each has its own pi_scout_<category>.txt.")
    grp.add_argument("--ads", action="store_true", help="Advertising, ad syndication, pop-ups")
    grp.add_argument("--tracking", action="store_true", help="Trackers, analytics, telemetry")
    grp.add_argument("--adult", action="store_true", help="Adult content")
    grp.add_argument("--other", action="store_true", help="Accept labels that fit no other category (combine with another flag)")
    grp.add_argument("--all", action="store_true", help="Every category (default)")
    ap.add_argument("--autostart", action="store_true", help="Start the live hunter immediately")
    ap.add_argument("--token", help="Fixed access token (default: generated once and remembered)")
    ap.add_argument("--no-auth", action="store_true", help="Disable the access token (only on a trusted network!)")
    args = ap.parse_args()

    if os.getuid() != 0:
        print("✗ Run as root (sudo): Pi-Scout reads the Pi-hole log and writes its blocklist.")
        sys.exit(1)
    core_path = find_core(args.core)
    if not core_path:
        print("✗ Could not find pi-scout.py. Put it next to this file or pass --core /path/to/pi-scout.py")
        sys.exit(1)
    core = load_core(core_path)
    cats = core.resolve_categories(args)
    if not (cats - {"other"}):
        print("✗ --other on its own has nothing to look at. Combine it with --ads, --tracking or --adult (or use --all).")
        sys.exit(1)
    core.ensure_category_files()  # creates the empty lists you register in Pi-hole once

    key = find_key(args.key)
    if key:
        os.environ["GEMINI_API_KEY"] = key
    NO_AUTH = args.no_auth
    TOKEN = get_token(args.token)
    ENGINE = Engine(core, args.aggression, categories=cats)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    host = lan_ip() if args.host in ("0.0.0.0", "") else args.host
    url = f"http://{host}:{args.port}/" + ("" if NO_AUTH else f"?token={TOKEN}")
    print(f"Pi-Scout UI  ·  core: {core_path}")
    print(f"  Categories: {core.categories_label()}   Aggression: {args.aggression}   Gemini key: {'found' if key else 'MISSING'}")
    print(f"  Open: {url}\n  Ctrl+C to quit.")
    if args.autostart:
        ok, msg = ENGINE.start("live")
        if not ok:
            print(f"  ⚠️ Could not autostart: {msg}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down…")
    finally:
        ENGINE.request_stop()
        if ENGINE.thread:
            ENGINE.thread.join(timeout=30)
        server.server_close()


if __name__ == "__main__":
    main()
