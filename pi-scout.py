#!/usr/bin/env python3
"""Pi-Scout — AI vanguard for Pi-hole (false-positive-hardened revision).

Gemini proposes blocks, but the code decides. Every proposal must survive:
  1. hard protections  (WHITELIST, never-block file, Pi-hole's own allowlist)
  2. sanity checks     (hostname was really submitted, not a local name, etc.)
  3. confidence gates  (stricter for wildcards than for exact hosts)
  4. wildcard purity   (no apex/www/login/shop/... hosts seen under that root)
Everything is logged with a reason so mistakes are easy to trace and undo.
"""
import os
import re
import sys
import time
import json
import shutil
import sqlite3
import argparse
import subprocess
from collections import defaultdict
from datetime import datetime
from google import genai
from google.genai import types

try:  # optional but recommended: pip install tldextract
    import tldextract
    _EXTRACT = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
    _EXTRACT("a.example.co.uk")  # self-test: the apt package ships without its bundled snapshot
except Exception:
    _EXTRACT = None  # fall back to the built-in suffix list in get_root()

ADD_LINE_FG = "30"  # 30 = Black Text
ADD_LINE_BG = "42"  # 42 = Green Background

MODEL = "gemini-3.5-flash-lite"
DB_PATH = "/etc/pihole/pihole-FTL.db"
GRAVITY_DB_PATH = "/etc/pihole/gravity.db"
LOG_FILE = "/var/log/pihole/pihole.log"
LIST_DIR = "/var/www/html"  # where the pi_scout_<category>.txt lists live
BACKUP_DIR = "/var/tmp/pi_scout_backups"  # a copy of any list is saved here before it is cleared
BACKLOG_PATH = "/var/tmp/pi_scout_backlog.json"
DECIDED_PATH = "/var/tmp/pi_scout_decided.json"           # domains Gemini already judged
NEVER_BLOCK_PATH = "/etc/pihole/pi_scout_never_block.txt"  # YOU edit this (one domain per line)
DECISION_LOG = "/var/log/pihole/pi_scout_decisions.jsonl"  # audit trail: what/why/confidence

BATCH_SIZE = 50
DECIDED_TTL = 7 * 24 * 3600   # don't re-ask Gemini about the same domain for a week
BATCH_WAIT = 60               # seconds to collect candidates before asking Gemini (fewer, richer batches)
GRAVITY_MIN_INTERVAL = 300    # run `pihole -g` at most once per 5 minutes

# --------------------------------------------------------------------------
# Categories: each one has its own blocklist file, pi_scout_<category>.txt
# --------------------------------------------------------------------------
CATEGORIES = ("ads", "tracking", "adult", "other")
ENABLED = set(CATEGORIES)   # categories that may be evaluated and written (--ads / --tracking / ...)
_DISABLED_SEEN = set()      # domains Gemini put in a disabled category (not re-asked this run)

# Keyword pre-filter: which domains are worth sending to Gemini, per category.
# "substr" matches anywhere; "tokens" only as whole words ("events.foo.com" yes, "eventbrite.com" no).
CATEGORY_KEYWORDS = {
    "ads": {
        "substr": ("videoplayerhub", "adserver", "adnetwork", "doubleclick", "popunder",
                   "syndication", "monetization", "outbrain", "teads"),
        "tokens": {"interstitial", "popup", "banner", "bidding"},
    },
    "tracking": {
        "substr": ("telemetry", "clickstream"),
        "tokens": {"analytics", "tracker", "attribution", "collector", "metrics", "events",
                   "beacon", "pixel", "sdk"},
    },
    "adult": {
        "substr": ("adult-", "-porn", "xxx", "nsfw", "cam-", "-tube", "escort"),
        "tokens": set(),
    },
}
CATEGORY_SCOPE = {  # what Gemini is told it may block, per category
    "ads": '- "ads": third-party advertising, ad exchanges, SSPs/DSPs, ad syndication, pop-ups/pop-unders',
    "tracking": '- "tracking": cross-site tracking, fingerprinting, data brokers, session replay, click/attribution '
                'measurement, and analytics/telemetry hostnames whose only purpose is collecting usage data',
    "adult": '- "adult": clearly adult-content sites',
}
CATEGORY_ALIASES = {  # Gemini's label -> our category; anything unknown becomes "other"
    "ads": "ads", "ad": "ads", "advertising": "ads", "adware": "ads", "popup": "ads", "popups": "ads",
    "popunder": "ads", "syndication": "ads",
    "tracking": "tracking", "tracker": "tracking", "analytics": "tracking", "telemetry": "tracking",
    "attribution": "tracking", "fingerprinting": "tracking",
    "adult": "adult", "porn": "adult", "nsfw": "adult",
}

# Suffix-matched (the domain itself and anything under it is never touched)
WHITELIST = {
    "apple.com", "icloud.com", "microsoft.com", "windows.com", "office.net",
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "amazon.com", "images-amazon.com", "cloudfront.net",
    "netflix.com", "disneyplus.com", "spotify.com", "playstation.net", "xboxlive.com",
    "fedex.com", "ups.com", "usps.com", "dhl.com", "paypal.com", "stripe.com",
    "openai.com", "chatgpt.com", "chase.com",
}

# Gemini may block individual hosts under these, but NEVER the whole root.
NEVER_WILDCARD = {
    # CDNs / cloud / hosting
    "amazonaws.com", "cloudfront.net", "akamaihd.net", "akamaized.net", "akamai.net",
    "edgekey.net", "edgesuite.net", "fastly.net", "fastlylb.net", "azureedge.net",
    "azurefd.net", "windows.net", "trafficmanager.net", "cloudflare.com", "cloudflare.net",
    "herokuapp.com", "appspot.com", "firebaseio.com", "firebaseapp.com", "web.app",
    "github.io", "githubusercontent.com", "vercel.app", "netlify.app", "workers.dev",
    "pages.dev", "blogspot.com", "wordpress.com", "googleusercontent.com", "gstatic.com",
    "jsdelivr.net", "unpkg.com", "bootstrapcdn.com", "fbcdn.net", "twimg.com", "ytimg.com",
    # bot defense / captcha / fraud
    "recaptcha.net", "hcaptcha.com", "perimeterx.net", "px-cloud.net", "datadome.co",
    "arkoselabs.com", "funcaptcha.com", "kasada.io",
    # APM / error monitoring (apps sometimes stall without them)
    "datadoghq.com", "newrelic.com", "nr-data.net", "sentry.io", "bugsnag.com",
    "crashlytics.com", "branch.io",
    # big multi-product platforms where ad hosts hide among real services
    "facebook.com", "instagram.com", "whatsapp.com", "youtube.com", "twitter.com",
    "x.com", "linkedin.com", "tiktok.com", "snapchat.com", "reddit.com",
    "samsung.com", "samsungcloud.com", "roku.com",
}

# Never block a hostname containing one of these labels (auth / payments / updates).
HARD_NEVER_LABELS = {
    "login", "signin", "auth", "sso", "oauth", "accounts", "account", "checkout",
    "pay", "payments", "secure", "mail", "webmail", "update", "updates", "ota",
    "download", "downloads", "time", "ntp",
}
# If any of these are seen under a root, the root is a real site/service -> no wildcard.
MIXED_USE_LABELS = HARD_NEVER_LABELS | {
    "www", "m", "app", "apps", "id", "my", "shop", "store", "support", "help",
    "docs", "portal",
}
LOCAL_TLDS = {"local", "lan", "home", "internal", "localdomain", "arpa", "localhost",
              "intranet", "corp", "private"}
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.mx", "com.cn", "com.tw", "com.hk",
    "co.in", "co.kr", "co.za", "com.sg", "com.tr", "com.ar",
}
HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$")


def normalize_category(raw):
    return CATEGORY_ALIASES.get(str(raw).strip().lower(), "other")


def set_enabled(cats):
    global ENABLED
    ENABLED = {c for c in cats if c in CATEGORIES}
    _DISABLED_SEEN.clear()


def resolve_categories(args):
    """--ads/--tracking/--adult/--other pick categories; --all (or none given) means every category."""
    picked = {c for c in CATEGORIES if getattr(args, c, False)}
    return set(CATEGORIES) if getattr(args, "all", False) or not picked else picked


def categories_label():
    return "all" if ENABLED == set(CATEGORIES) else ", ".join(c for c in CATEGORIES if c in ENABLED)


def category_path(cat):
    return os.path.join(LIST_DIR, f"pi_scout_{cat}.txt")


def blocklist_files():
    return [category_path(c) for c in CATEGORIES]


def scope_text():
    return "\n".join(CATEGORY_SCOPE[c] for c in CATEGORIES if c in ENABLED and c in CATEGORY_SCOPE)


def cats_text():
    return "|".join(c for c in CATEGORIES if c in ENABLED and c in CATEGORY_SCOPE)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def get_timestamp():
    return f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"


def format_color_line(text):
    return f"\033[{ADD_LINE_FG};{ADD_LINE_BG}m{text}\033[0m"


def valid_hostname(domain):
    return bool(HOST_RE.match(domain)) and domain.rsplit(".", 1)[-1] not in LOCAL_TLDS


def in_suffix_set(domain, suffixes):
    """True if domain, or any parent of it, is in `suffixes`."""
    labels = domain.split(".")
    return any(".".join(labels[i:]) in suffixes for i in range(len(labels)))


def get_root(domain):
    """Registrable domain (example.co.uk), or '' if there isn't one."""
    if _EXTRACT:
        res = _EXTRACT(domain)
        root = getattr(res, "top_domain_under_public_suffix", None)  # newer tldextract
        if root is None:
            root = res.registered_domain  # older tldextract
        return root.lower()
    labels = domain.split(".")
    if len(labels) < 2:
        return ""
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:]) if len(labels) >= 3 else ""
    return ".".join(labels[-2:])


def host_labels(domain):
    """Labels to the left of the registrable root: a.b.example.com -> ['a','b']."""
    root = get_root(domain)
    if not root or domain == root:
        return []
    return domain[: -(len(root) + 1)].split(".")


def is_false_positive_pattern(domain):
    if domain.startswith(("click.", "clicks.", "link.")):
        if not any(t in domain for t in ["doubleclick", "rubicon", "pubmatic", "adnxs"]):
            return True
    if "cardcommunication" in domain or "transaction" in domain or "statement" in domain:
        return True
    return False


def matching_categories(domain):
    """Which categories' keywords this hostname matches."""
    cats, tokens = set(), None
    for cat, spec in CATEGORY_KEYWORDS.items():
        if any(s in domain for s in spec["substr"]):
            cats.add(cat)
            continue
        if spec["tokens"]:
            if tokens is None:
                tokens = set(re.split(r"[.\-_0-9]+", domain))
            if spec["tokens"] & tokens:
                cats.add(cat)
    return cats


def looks_like_tracker(domain, enabled=None):
    cats = matching_categories(domain)
    return bool(cats & (ENABLED if enabled is None else set(enabled)))


def thresholds(aggression):
    """(wildcard_min, exact_min) confidence. Wildcards always need more certainty."""
    return max(85, 100 - 2 * aggression), max(75, 95 - 2 * aggression)


# --------------------------------------------------------------------------
# State on disk
# --------------------------------------------------------------------------
def _load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception as e:
        print(f"{get_timestamp()} ✗ Error saving {path}: {e}")


def load_disk_backlog():
    data = _load_json(BACKLOG_PATH, [])
    return set(data) if isinstance(data, list) else set()


def save_disk_backlog(queue_set):
    _save_json(BACKLOG_PATH, list(queue_set))


def reset_categories(cats):
    """Empty the chosen category lists and forget everything tied to them, so those domains are judged afresh.

    Only call this while nothing is running (the dashboard enforces that). Kept in sync: the "already judged"
    memory (DECIDED_PATH) and the retry backlog (BACKLOG_PATH) lose the domains tied to the cleared
    categories -- those whose name matches the category's keywords, plus anything under a rule that was
    removed. Clearing every category empties both completely. A copy of each list is saved to BACKUP_DIR."""
    cats = [c for c in CATEGORIES if c in set(cats)]
    everything = set(cats) == set(CATEGORIES)
    removed, rule_hosts = {}, set()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for cat in cats:
        path = category_path(cat)
        wild, exact = parse_blocklist(path)
        removed[cat] = len(wild) + len(exact)
        rule_hosts |= wild | exact
        if removed[cat]:
            try:
                os.makedirs(BACKUP_DIR, exist_ok=True)
                shutil.copy2(path, os.path.join(BACKUP_DIR, f"pi_scout_{cat}.txt.{stamp}"))
            except OSError:
                pass
        open(path, "w").close()
    keyword_cats = {c for c in cats if c in CATEGORY_KEYWORDS}

    def tied(domain):
        return everything or bool(matching_categories(domain) & keyword_cats) or in_suffix_set(domain, rule_hosts)

    decided = load_decided()
    gone_d = [k for k in list(decided) if tied(k)]
    for k in gone_d:
        del decided[k]
    _save_json(DECIDED_PATH, decided)
    queue = load_disk_backlog()
    gone_q = [k for k in list(queue) if tied(k)]
    for k in gone_q:
        queue.discard(k)
    save_disk_backlog(queue)
    _DISABLED_SEEN.clear()
    return {"removed": removed, "decided": len(gone_d), "backlog": len(gone_q)}


def load_decided():
    data = _load_json(DECIDED_PATH, {})
    now = time.time()
    return {d: t for d, t in data.items() if now - t < DECIDED_TTL} if isinstance(data, dict) else {}


def parse_blocklist(path):
    """Returns (wildcard_roots, exact_hosts) found in one blocklist file."""
    wild, exact = set(), set()
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("||"):
                    wild.add(line[2:].rstrip("^"))
                else:
                    exact.add(line)
    return wild, exact


def load_blocks_by_file():
    return {p: parse_blocklist(p) for p in blocklist_files()}


def load_current_blocks():
    """Returns (wildcard_roots, exact_hosts) already blocked by any Pi-Scout file."""
    wild, exact = set(), set()
    for w, e in load_blocks_by_file().values():
        wild |= w
        exact |= e
    return wild, exact


def ensure_category_files():
    """Create any missing (empty) category files so you can register them in Pi-hole once."""
    created = []
    os.makedirs(LIST_DIR, exist_ok=True)
    for cat in CATEGORIES:
        path = category_path(cat)
        if not os.path.exists(path):
            open(path, "a").close()
            created.append(path)
    if created:
        print(f"{get_timestamp()} 🗂️ Created {len(created)} empty category list(s). Register each once in Pi-hole "
              f"(Adlists), using the same kind of address as your existing list:")
        for p in created:
            print(f"      {os.path.basename(p)}   ({p})")
    return created


def load_never_block():
    out = set()
    if os.path.exists(NEVER_BLOCK_PATH):
        with open(NEVER_BLOCK_PATH, "r") as f:
            for line in f:
                line = line.split("#")[0].strip().lower()
                if line:
                    out.add(line)
    return out


def load_pihole_allowlist():
    """Domains you've allowed in Pi-hole itself are sacred: never re-block them."""
    exact, regexes = set(), []
    try:
        conn = sqlite3.connect(f"file:{GRAVITY_DB_PATH}?mode=ro", uri=True, timeout=10)
        for domain, dtype in conn.execute("SELECT domain, type FROM domainlist WHERE enabled=1 AND type IN (0,2)"):
            if dtype == 0:
                exact.add(domain.lower())
            else:
                try:
                    regexes.append(re.compile(domain, re.I))
                except re.error:
                    pass
        conn.close()
    except Exception as e:
        print(f"{get_timestamp()} ⚠️ Could not read Pi-hole allowlist ({e}); continuing without it.")
    return exact, regexes


class Guard:
    """Everything that says 'hands off' or 'already handled', refreshed periodically."""

    def __init__(self):
        self.wild, self.exact, self.never = set(), set(), set()
        self.allow_exact, self.allow_regex = set(), []
        self.loaded_at = 0.0

    def refresh(self, force=False):
        if not force and time.time() - self.loaded_at < 300:
            return
        self.wild, self.exact = load_current_blocks()
        self.never = load_never_block()
        self.allow_exact, self.allow_regex = load_pihole_allowlist()
        self.loaded_at = time.time()

    def is_blocked(self, d):
        return d in self.exact or in_suffix_set(d, self.wild)

    def is_protected(self, d):
        return (in_suffix_set(d, WHITELIST) or in_suffix_set(d, self.never)
                or d in self.allow_exact or any(r.search(d) for r in self.allow_regex))


class FamilyIndex:
    """What hostnames exist under each root on YOUR network (last 14 days).
    This is the evidence used to decide whether a wildcard is safe."""

    def __init__(self, days=14, ttl=1800):
        self.days, self.ttl = days, ttl
        self.by_root = defaultdict(dict)
        self.loaded_at = 0.0
        self.ok = False

    def refresh(self, force=False):
        if not force and time.time() - self.loaded_at < self.ttl:
            return
        by_root = defaultdict(dict)
        try:
            conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=15)
            cutoff = int(time.time()) - self.days * 86400
            for d, c in conn.execute("SELECT domain, COUNT(*) FROM queries WHERE timestamp > ? GROUP BY domain", (cutoff,)):
                d = (d or "").lower()
                root = get_root(d)
                if root:
                    by_root[root][d] = c
            conn.close()
            self.ok = True
        except Exception as e:
            self.ok = False
            print(f"{get_timestamp()} ⚠️ Could not build family index ({e}); wildcards will be downgraded to exact hosts.")
        self.by_root = by_root
        self.loaded_at = time.time()

    def hosts(self, root):
        return self.by_root.get(root, {})


def family_is_pure(root, covered, fam):
    """A wildcard is only safe if nothing under the root looks like a real site/service."""
    if not fam.ok:
        return False, "no query history available to verify the family"
    hosts = set(fam.hosts(root)) | set(covered)
    if root in hosts:
        return False, "apex domain is queried directly (looks like a real site)"
    for h in hosts:
        if MIXED_USE_LABELS.intersection(host_labels(h)):
            return False, f"family contains user-facing host {h}"
    return True, ""


# --------------------------------------------------------------------------
# Gemini
# --------------------------------------------------------------------------
PROMPT_TEMPLATE = """You are a careful DNS analyst tuning a home Pi-hole. The hostnames below were ALLOWED (not blocked) and were pre-selected by crude keyword matching, so MANY OF THEM ARE LEGITIMATE.

A wrong block breaks real websites and apps for the whole household. A missed ad costs almost nothing. Your default answer is "do not block". When unsure, leave the domain out. An empty "decisions" list is a perfectly good answer.

INPUT: JSON list of groups. Each group has a registrable "root", the "candidates" under evaluation (host + query count), and "other_hosts_seen": other hostnames under the same root observed on this network (context for judging the whole family), and "already_blocked": hosts under this root that are ALREADY blocked, which are your own earlier decisions. Stay consistent with them: if the root now has several blocked ad/tracking hosts and nothing that looks like a real service, block_root is the natural next step.

MAY BE BLOCKED (ONLY these categories are in scope; omit everything else, even if it looks bad):
__SCOPE__

NEVER BLOCK (omit these):
- first-party APIs/backends of an app or site, login/SSO/OAuth, payments/fraud checks, email, captive-portal/connectivity checks, OS/firmware/app updates, push notifications, smart-home/IoT/game services, streaming media delivery, CDNs, cloud hosting, DNS/routing, bot defense/captcha
- a hostname merely because it contains words like events, metrics, sdk, pixel, collector, beacon

ACTIONS:
- "block_exact": that exact hostname is ad/tracking/telemetry/adult; the root may have legitimate uses.
- "block_root": wildcard for the ENTIRE root. Use ONLY if (a) the company behind the root does nothing except advertising/tracking/data collection, AND (b) every host in candidates and other_hosts_seen is ad/tracking, AND (c) no user-facing site, app, API or CDN lives under it. Never use it for large platforms that also sell non-ad products. If any observed host looks like a normal website or app, use block_exact for the bad hosts instead.
__POLICY__

OUTPUT: raw JSON only, no markdown:
{"decisions":[{"domain":"...","action":"block_exact","confidence":0,"category":"__CATS__","reason":"max 12 words"}]}
- For block_root, "domain" MUST be the group's root exactly as given. For block_exact, "domain" MUST be a candidate host verbatim.
- "confidence" is your honest probability (0-100) that the domain really is what you say AND blocking it breaks nothing a household would want. Use 80 or less when unsure.
- Omit every domain you would allow.

DATA:
__DATA__
"""


def wildcard_policy(aggression):
    if aggression <= 3:
        return ("WILDCARD POLICY (conservative): use block_root only for roots that are unmistakably "
                "dedicated ad/tracking networks. Prefer block_exact.")
    if aggression >= 8:
        return ("WILDCARD POLICY (aggressive): prefer block_root for any root that is clearly an "
                "ad-tech/tracking company, even if only a few hosts were observed, as long as every "
                "safety condition above holds.")
    return ("WILDCARD POLICY (balanced): use block_root for clear-cut ad/tracking roots; default to "
            "block_exact for anything ambiguous.")


def build_groups(batch, fam, guard=None):
    grouped = defaultdict(list)
    for d in batch:
        grouped[get_root(d) or d].append(d)
    groups = []
    for root, hosts in grouped.items():
        seen = fam.hosts(root)
        others = sorted((h for h in seen if h not in hosts), key=lambda h: -seen[h])[:12]
        already = []
        if guard is not None:  # what we already decided under this root, so decisions stay consistent
            already = sorted(h for h in guard.exact if h == root or h.endswith("." + root))[:12]
            already += sorted("||" + h + "^" for h in guard.wild if h.endswith("." + root))[:6]
        groups.append({
            "root": root,
            "candidates": [{"host": h, "queries": seen.get(h, 1)} for h in sorted(hosts)],
            "other_hosts_seen": others,
            "already_blocked": already,
        })
    return groups


def query_gemini(groups, aggression):
    client = genai.Client()
    prompt = (PROMPT_TEMPLATE
              .replace("__POLICY__", wildcard_policy(aggression))
              .replace("__SCOPE__", scope_text())
              .replace("__CATS__", cats_text())
              .replace("__DATA__", json.dumps(groups)))
    response = client.models.generate_content(
        model=MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0),
    )
    data = json.loads(response.text)
    decisions = data.get("decisions", []) if isinstance(data, dict) else []
    return decisions if isinstance(decisions, list) else []


# --------------------------------------------------------------------------
# The code-side judge
# --------------------------------------------------------------------------
def evaluate(decisions, batch, guard, fam, aggression):
    """Turn Gemini's proposals into (accepted, rejected) entries. Gemini never writes directly."""
    wmin, emin = thresholds(aggression)
    batch_set = set(batch)
    accepted, rejected = [], []

    def entry(kind, value, meta, note=""):
        return {"kind": kind, "value": value, "confidence": meta["confidence"],
                "category": meta["category"], "reason": meta["reason"], "note": note}

    def exact_problem(d, conf):
        if d not in batch_set:
            return "not one of the submitted hostnames"
        if not valid_hostname(d):
            return "invalid or local hostname"
        if guard.is_protected(d):
            return "protected (whitelist / Pi-hole allowlist / never-block file)"
        if guard.is_blocked(d):
            return "already blocked"
        if HARD_NEVER_LABELS.intersection(host_labels(d)):
            return "auth/payment/update-style hostname"
        if conf < emin:
            return f"confidence {conf:.0f} below exact-host minimum {emin}"
        return None

    for dec in decisions:
        if not isinstance(dec, dict):
            continue
        action = str(dec.get("action", "")).lower()
        domain = str(dec.get("domain", "")).lower().strip().rstrip(".")
        try:
            conf = float(dec.get("confidence", 0))
        except (TypeError, ValueError):
            conf = 0.0
        meta = {"confidence": conf, "category": normalize_category(dec.get("category", "")),
                "reason": str(dec.get("reason", ""))[:120]}

        if action in ("block_exact", "block_root") and meta["category"] not in ENABLED:
            hosts = [domain] if action == "block_exact" else sorted(
                d for d in batch_set if d == domain or d.endswith("." + domain))
            e = entry("wildcard" if action == "block_root" else "exact", domain, meta,
                      f"category '{meta['category']}' is not enabled")
            e["undecided"] = hosts  # don't count these as judged: enabling the category later should retry them
            rejected.append(e)
            continue

        if action == "block_exact":
            problem = exact_problem(domain, conf)
            (accepted if problem is None else rejected).append(entry("exact", domain, meta, problem or ""))

        elif action == "block_root":
            covered = sorted(d for d in batch_set if d == domain or d.endswith("." + domain))
            problem = None
            if not domain or get_root(domain) != domain:
                problem = "not a registrable root domain"
            elif not covered:
                problem = "root has no submitted hostnames"
            elif guard.is_blocked(domain):
                problem = "already blocked"
            if problem:
                rejected.append(entry("wildcard", domain, meta, problem))
                continue

            if guard.is_protected(domain):
                rejected.append(entry("wildcard", domain, meta, "protected root"))
                continue
            downgrade = None
            if in_suffix_set(domain, NEVER_WILDCARD):
                downgrade = "shared infrastructure / multi-product platform"
            elif conf < wmin:
                downgrade = f"confidence {conf:.0f} below wildcard minimum {wmin}"
            else:
                pure, why = family_is_pure(domain, covered, fam)
                if not pure:
                    downgrade = why
            if downgrade is None:
                accepted.append(entry("wildcard", domain, meta))
                continue

            rejected.append(entry("wildcard", domain, meta, f"wildcard refused: {downgrade}"))
            for d in covered:  # fall back to exact hosts, each judged on its own
                p = exact_problem(d, conf)
                (accepted if p is None else rejected).append(
                    entry("exact", d, meta, p or f"downgraded from wildcard ||{domain}^"))

    wild_roots = {e["value"] for e in accepted if e["kind"] == "wildcard"}
    seen, final = set(), []
    for e in accepted:
        key = (e["kind"], e["value"])
        if key in seen or (e["kind"] == "exact" and in_suffix_set(e["value"], wild_roots)):
            continue
        seen.add(key)
        final.append(e)
    return final, rejected


def log_decisions(accepted, rejected):
    try:
        os.makedirs(os.path.dirname(DECISION_LOG), exist_ok=True)
        now = time.time()
        with open(DECISION_LOG, "a") as f:
            for e in accepted:
                f.write(json.dumps({"ts": now, "applied": True, **e}) + "\n")
            for e in rejected:
                clean = {k: v for k, v in e.items() if k != "undecided"}
                f.write(json.dumps({"ts": now, "applied": False, **clean}) + "\n")
    except OSError:
        pass


def run_gravity():
    print(f"{get_timestamp()} 🔄 Triggering Pi-hole gravity update (`pihole -g`)...")
    result = subprocess.run(["pihole", "-g"], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"{get_timestamp()} ✓ Gravity updated successfully.")
    else:
        print(f"{get_timestamp()} ✗ Error running gravity update: {result.stderr.strip()}")


_gravity_pending = False
_last_gravity = 0.0


def maybe_run_gravity(force=False):
    """Debounced gravity: rules are written immediately, ingested at most every GRAVITY_MIN_INTERVAL."""
    global _gravity_pending, _last_gravity
    if not _gravity_pending:
        return
    if not force and time.time() - _last_gravity < GRAVITY_MIN_INTERVAL:
        return
    _gravity_pending = False
    _last_gravity = time.time()
    run_gravity()


def _supersede(root, guard):
    """A new wildcard makes exact rules (and narrower wildcards) under that root redundant: remove them."""
    removed = []
    for path in blocklist_files():
        if not os.path.exists(path):
            continue
        with open(path, "r") as f:
            lines = f.read().splitlines()
        kept = []
        for l in lines:
            raw = l.strip().lower()
            is_wild = raw.startswith("||")
            host = raw[2:].rstrip("^") if is_wild else raw
            if raw and not raw.startswith("#") and (host.endswith("." + root) or (host == root and not is_wild)):
                removed.append(host)
            else:
                kept.append(l)
        if len(kept) != len(lines):
            with open(path, "w") as f:
                f.write("\n".join(kept) + ("\n" if kept else ""))
    for h in removed:
        guard.exact.discard(h)
        guard.wild.discard(h)
    return removed


def request_gravity_now():
    """Run gravity right away (used after a clear) instead of waiting for the debounce interval."""
    global _gravity_pending
    _gravity_pending = True
    maybe_run_gravity(force=True)


def commit(entries, guard):
    global _gravity_pending
    if not entries:
        return 0
    by_file, count = defaultdict(list), 0
    for e in entries:
        if e["kind"] == "wildcard":
            line, label = f"||{e['value']}^", "Wildcard Root"
            guard.wild.add(e["value"])
        else:
            line, label = e["value"], "Exact Subdomain"
            guard.exact.add(e["value"])
        cat = e.get("category") if e.get("category") in CATEGORIES else "other"
        path = category_path(cat)
        by_file[path].append(line)
        count += 1
        print(format_color_line(
            f"{get_timestamp()} ⚡ Added {label}: {line}  "
            f"[{e['confidence']:.0f}% {cat}: {e['reason']}] -> {os.path.basename(path)}"))
    os.makedirs(LIST_DIR, exist_ok=True)
    for path, lines in by_file.items():
        with open(path, "a") as f:
            f.write("\n".join(lines) + "\n")
    for e in entries:  # a wildcard replaces earlier, narrower rules under the same root
        if e["kind"] == "wildcard":
            e["superseded"] = _supersede(e["value"], guard)
            if e["superseded"]:
                n = len(e["superseded"])
                shown = ", ".join(e["superseded"][:3]) + (f" +{n - 3} more" if n > 3 else "")
                print(f"{get_timestamp()}    ↳ replaces {n} narrower rule{'s' if n != 1 else ''}: {shown}")
    _gravity_pending = True
    maybe_run_gravity()
    return count


def process_batch(batch, guard, fam, decided, aggression):
    guard.refresh()
    fam.refresh()
    decisions = query_gemini(build_groups(batch, fam, guard), aggression)  # raises on API error -> caller retries
    accepted, rejected = evaluate(decisions, batch, guard, fam, aggression)
    log_decisions(accepted, rejected)
    for r in rejected:
        print(f"{get_timestamp()} 🛑 Rejected {r['kind']} {r['value']}: {r['note']}")
    applied = commit(accepted, guard)
    skip = set()
    for r in rejected:
        skip.update(r.get("undecided", ()))
    _DISABLED_SEEN.update(skip)  # not re-asked this run, but retried if you enable the category later
    now = time.time()
    for d in batch:  # remember we judged these, so one unlucky re-roll can't block them later
        if d not in skip:
            decided[d] = now
    _save_json(DECIDED_PATH, decided)
    return applied


def is_candidate(domain, guard, decided):
    if not valid_hostname(domain):
        return False
    if guard.is_protected(domain) or guard.is_blocked(domain):
        return False
    if is_false_positive_pattern(domain):
        return False
    if domain in _DISABLED_SEEN:
        return False
    if time.time() - decided.get(domain, 0) < DECIDED_TTL:
        return False
    return looks_like_tracker(domain)


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------
def run_database_audit(aggression):
    print(f"{get_timestamp()} 📖 Mode Selected: [Long-Term History Gatherer] (Aggression: {aggression}/10) · Categories: {categories_label()}")
    if not os.path.exists(DB_PATH):
        print(f"{get_timestamp()} ✗ Error: Pi-hole SQLite database not found at {DB_PATH}")
        return
    guard = Guard()
    guard.refresh(force=True)
    fam = FamilyIndex()
    fam.refresh(force=True)
    decided = load_decided()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    thirty_days_ago = int(time.time()) - (30 * 24 * 60 * 60)
    try:
        cursor.execute("SELECT DISTINCT domain FROM queries WHERE status IN (2, 3) AND timestamp > ?", (thirty_days_ago,))
        rows = cursor.fetchall()
    except sqlite3.OperationalError:
        cursor.execute("SELECT DISTINCT domain FROM queries WHERE status IN (2, 3)")
        rows = cursor.fetchall()
    conn.close()

    candidates = sorted({(r[0] or "").lower() for r in rows})
    candidates = [d for d in candidates if is_candidate(d, guard, decided)]
    if not candidates:
        print(f"{get_timestamp()} ✨ Clean scan! No unblocked trends found.")
        return

    print(f"{get_timestamp()} 🧠 Consulting Gemini AI to audit {len(candidates)} historical candidates...")
    total = 0
    for i in range(0, len(candidates), BATCH_SIZE):
        chunk = candidates[i:i + BATCH_SIZE]
        try:
            total += process_batch(chunk, guard, fam, decided, aggression)
        except Exception as e:
            print(f"{get_timestamp()} ✗ Audit API Error: {e}. Stopping; re-run later to continue.")
            break
        time.sleep(2)  # be kind to free-tier rate limits
    maybe_run_gravity(force=True)
    print(f"{get_timestamp()} ✓ Audit complete. Committed {total} rules.")


def run_live_hunter(aggression):
    print(f"{get_timestamp()} 📡 Mode Selected: [Always-On Live Hunter with Retry Caching] (Aggression: {aggression}/10) · Categories: {categories_label()}")
    print(f"{get_timestamp()} 🛡️ Layered false-positive guards, decision memory and resilient caching are ACTIVE.")

    guard = Guard()
    guard.refresh(force=True)
    fam = FamilyIndex()
    fam.refresh(force=True)
    decided = load_decided()
    batch_queue = {d for d in load_disk_backlog() if is_candidate(d, guard, decided)}
    if batch_queue:
        print(f"{get_timestamp()} 📦 Loaded {len(batch_queue)} backlogged domains from disk cache for retry.")

    last_batch_time = time.time()
    next_allowed_api_time = 0.0
    backoff_seconds = 30

    f = open(LOG_FILE, "r")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        now = time.time()
        guard.refresh()
        maybe_run_gravity()

        if batch_queue and now >= next_allowed_api_time and (now - last_batch_time >= BATCH_WAIT or len(batch_queue) >= BATCH_SIZE):
            stale = [d for d in list(batch_queue)[:BATCH_SIZE] if not is_candidate(d, guard, decided)]
            batch_queue.difference_update(stale)
            chunk = list(batch_queue)[:BATCH_SIZE]
            if chunk:
                print(f"{get_timestamp()} 🧠 Sending batch of {len(chunk)} live candidates to Gemini AI...")
                try:
                    process_batch(chunk, guard, fam, decided, aggression)
                    batch_queue.difference_update(chunk)
                    save_disk_backlog(batch_queue)
                    last_batch_time = now
                    backoff_seconds = 30
                except Exception as e:
                    print(f"{get_timestamp()} ⚠️ API Error (Retrying later): {e}")
                    print(f"{get_timestamp()} 🛡️ Caching {len(chunk)} domains. Backing off for {backoff_seconds}s...")
                    save_disk_backlog(batch_queue)
                    next_allowed_api_time = now + backoff_seconds
                    backoff_seconds = min(backoff_seconds * 2, 300)

        line = f.readline()
        if not line:
            try:  # follow log rotation / truncation
                st = os.stat(LOG_FILE)
                if st.st_ino != inode or st.st_size < f.tell():
                    f.close()
                    f = open(LOG_FILE, "r")
                    inode = os.fstat(f.fileno()).st_ino
            except OSError:
                pass
            time.sleep(0.1)
            continue

        if "reply " in line and " is " in line:
            try:
                parts = line.split()
                domain = parts[parts.index("reply") + 1].lower().rstrip(".")
            except (ValueError, IndexError):
                continue
            if domain not in batch_queue and is_candidate(domain, guard, decided):
                print(f"{get_timestamp()} 🔍 Queueing candidate for evaluation: {domain}")
                batch_queue.add(domain)
                save_disk_backlog(batch_queue)


def run_allow(domain):
    """Fix a false positive in one command: never block it again and unblock it now."""
    domain = domain.lower().strip().rstrip(".")
    if not valid_hostname(domain):
        print(f"{get_timestamp()} ✗ '{domain}' doesn't look like a valid hostname.")
        return
    os.makedirs(os.path.dirname(NEVER_BLOCK_PATH), exist_ok=True)
    if domain not in load_never_block():
        with open(NEVER_BLOCK_PATH, "a") as f:
            f.write(domain + "\n")
    print(f"{get_timestamp()} ✓ Added {domain} (and everything under it) to the never-block file.")

    removed = False
    for path in blocklist_files():
        if not os.path.exists(path):
            continue
        with open(path, "r") as f:
            lines = f.read().splitlines()
        kept = [l for l in lines if l.strip().replace("||", "").replace("^", "").lower() != domain]
        if len(kept) != len(lines):
            with open(path, "w") as f:
                f.write("\n".join(kept) + ("\n" if kept else ""))
            removed = True
            print(f"{get_timestamp()} ✓ Removed {domain} from {os.path.basename(path)}.")

    wild, _ = load_current_blocks()
    parents = [p for p in wild if p != domain and (domain.endswith("." + p))]
    subprocess.run(["pihole", "allow", domain], capture_output=True, text=True)
    if parents:
        print(f"{get_timestamp()} ℹ️ A wildcard still covers it: {', '.join('||' + p + '^' for p in parents)}. "
              f"`pihole allow` exempts this exact host; run --allow on the root to drop the whole wildcard.")
    if removed:
        run_gravity()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pi-Scout — Unified AI Vanguard for Pi-hole")
    parser.add_argument("--audit", action="store_true", help="Scan the last 30 days of allowed lookups once, then exit (instead of watching live)")
    parser.add_argument("--key", "--gemini-key", dest="gemini_key", help="Gemini API Key")
    parser.add_argument("--aggression", type=int, default=7, choices=range(1, 11),
                        help="1 (conservative/exact-heavy) to 10 (aggressive wildcarding). Default 7. Safety guards apply at every level.")
    cat = parser.add_argument_group("categories", "Choose what to look for; each category has its own pi_scout_<category>.txt. Default: --all.")
    cat.add_argument("--ads", action="store_true", help="Advertising, ad syndication, pop-ups")
    cat.add_argument("--tracking", action="store_true", help="Trackers, analytics, telemetry")
    cat.add_argument("--adult", action="store_true", help="Adult content")
    cat.add_argument("--other", action="store_true", help="Accept labels Gemini returns that fit no other category (combine with another flag)")
    cat.add_argument("--all", action="store_true", help="Every category (the default when no category flag is given)")
    parser.add_argument("--allow", metavar="DOMAIN", help="Mark DOMAIN as a false positive: unblock it and never block it again")
    args = parser.parse_args()
    set_enabled(resolve_categories(args))

    if os.getuid() != 0:
        print(f"{get_timestamp()} ✗ Execution Error: Run as root (sudo).")
        sys.exit(1)

    if args.allow:
        run_allow(args.allow)
        sys.exit(0)

    if args.gemini_key:
        os.environ["GEMINI_API_KEY"] = args.gemini_key
    if not os.environ.get("GEMINI_API_KEY"):
        print(f"{get_timestamp()} ✗ Error: Gemini API Key is missing. Pass it via --key <YOUR_KEY> or set the GEMINI_API_KEY environment variable.")
        sys.exit(1)

    if not (ENABLED - {"other"}):
        print(f"{get_timestamp()} ✗ --other on its own has nothing to look at. Combine it with --ads, --tracking or --adult (or use --all).")
        sys.exit(1)
    ensure_category_files()

    try:
        if args.audit:
            run_database_audit(args.aggression)
        else:
            run_live_hunter(args.aggression)
    except KeyboardInterrupt:
        maybe_run_gravity(force=True)  # ingest any rules written but not yet loaded
        print(f"\n{get_timestamp()} 👋 Script safely paused.")
