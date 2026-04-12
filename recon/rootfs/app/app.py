#!/usr/bin/env python3
import subprocess
import shutil
import os
import re
import tempfile
import urllib.request
from flask import Flask, render_template, request, Response, stream_with_context, jsonify

# Valid username chars for SSH/FTP/common services
_VALID_USER_RE = re.compile(r'^[a-zA-Z0-9_\-\.@]{1,64}$')

app = Flask(__name__)

INGRESS_PATH = os.environ.get("INGRESS_PATH", "")
INGRESS_PORT = int(os.environ.get("INGRESS_PORT", 8765))

# Bundled lists (baked into image)
WORDLIST_BASE = os.path.join(os.path.dirname(__file__), "wordlists")
# Persistent custom lists (HA /data volume)
CUSTOM_BASE = "/data/wordlists"

SECLISTS_RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"

# Maps bundled filename → SecLists path (for update checks)
WORDLIST_SOURCES = {
    "usernames": {
        "top-usernames-shortlist.txt":  "Usernames/top-usernames-shortlist.txt",
        "cirt-default-usernames.txt":   "Usernames/cirt-default-usernames.txt",
    },
    "webpaths": {
        "common.txt":                 "Discovery/Web-Content/common.txt",
        "big.txt":                    "Discovery/Web-Content/big.txt",
        "raft-medium-directories.txt":"Discovery/Web-Content/raft-medium-directories.txt",
    },
    "passwords": {
        "top-passwords-shortlist.txt":      "Passwords/Common-Credentials/top-passwords-shortlist.txt",
        "top-20-common-SSH-passwords.txt":  "Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
        "2025-199_most_used_passwords.txt": "Passwords/Common-Credentials/2025-199_most_used_passwords.txt",
        "darkweb2017_top-100.txt":          "Passwords/Common-Credentials/darkweb2017_top-100.txt",
        "darkweb2017_top-1000.txt":         "Passwords/Common-Credentials/darkweb2017_top-1000.txt",
        "10k-most-common.txt":              "Passwords/Common-Credentials/10k-most-common.txt",
        "ssh-betterdefaultpasslist.txt":    "Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt",
        "ftp-betterdefaultpasslist.txt":    "Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
        "probable-v2-wpa-top4800.txt":      "Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
    },
}

# Protocol-specific Hydra tuning hints (for the UI)
PROTO_HINTS = {
    "ssh":       {"tasks": 1, "wait_ms": 3000, "note": "SSH: Fail2ban-Schutz. ≥1000ms nötig, 3000ms sicher."},
    "rdp":       {"tasks": 1, "wait_ms": 3000, "note": "RDP: Sperrt bei vielen Fehlversuchen. 3000ms empfohlen."},
    "smb":       {"tasks": 1, "wait_ms": 2000, "note": "SMB: ≥1000ms empfohlen, 2000ms sicher."},
    "telnet":    {"tasks": 4, "wait_ms": 500,  "note": "Telnet: 500ms reicht meist aus."},
    "ftp":       {"tasks": 4, "wait_ms": 300,  "note": "FTP: Kein Rate-Limit. 0–500ms."},
    "pop3":      {"tasks": 4, "wait_ms": 300,  "note": "POP3: 0–500ms."},
    "smtp":      {"tasks": 4, "wait_ms": 300,  "note": "SMTP: 0–500ms."},
    "http-get":       {"tasks": 8, "wait_ms": 0, "note": "HTTP GET: Kein Wait nötig. Nur für HTTP Basic Auth."},
    "https-get":      {"tasks": 8, "wait_ms": 0, "note": "HTTPS GET: Kein Wait nötig. Nur für HTTP Basic Auth."},
    "http-post-form": {"tasks": 8, "wait_ms": 0, "note": "HTTP POST Form: Für HTML Login-Formulare. Auto-Detect nutzen!"},
    "https-post-form":{"tasks": 8, "wait_ms": 0, "note": "HTTPS POST Form: Für HTML Login-Formulare. Auto-Detect nutzen!"},
}


def run_streaming(cmd):
    """Run a command and stream output line by line via SSE with keepalive."""
    def generate():
        import select as sel
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            fd = process.stdout.fileno()
            while True:
                ready, _, _ = sel.select([fd], [], [], 15)
                if ready:
                    line = process.stdout.readline()
                    if line == '':
                        break
                    yield f"data: {line.rstrip()}\n\n"
                else:
                    yield ": keep-alive\n\n"
                if process.poll() is not None:
                    for line in process.stdout:
                        yield f"data: {line.rstrip()}\n\n"
                    break
            process.wait()
            yield f"data: [DONE] Exit code: {process.returncode}\n\n"
        except FileNotFoundError:
            yield f"data: [ERROR] Befehl nicht gefunden: {cmd[0]}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {str(e)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"}
    )


ADDON_VERSION = "1.4.0"

@app.route("/")
def index():
    return render_template(
        "index.html",
        ingress_path=INGRESS_PATH,
        version=ADDON_VERSION,
        has_rustscan=shutil.which("rustscan") is not None,
        has_nmap=shutil.which("nmap") is not None,
        has_iw=shutil.which("iw") is not None,
        has_iwlist=shutil.which("iwlist") is not None,
        has_airodump=shutil.which("airodump-ng") is not None,
        has_hydra=shutil.which("hydra") is not None,
        has_nikto=shutil.which("nikto") is not None,
        has_ffuf=shutil.which("ffuf") is not None,
    )


# ── IP / Port Scanner ──────────────────────────────────────────────────────────

@app.route("/scan/nmap")
def scan_nmap():
    target = request.args.get("target", "").strip()
    profile = request.args.get("profile", "quick")
    if not target:
        return Response("data: [ERROR] Kein Ziel angegeben\n\n", mimetype="text/event-stream")
    profiles = {
        "quick":   ["-T4", "--open", "-F"],
        "fast":    ["-T4", "--open", "-p-", "--min-rate", "5000"],
        "service": ["-T4", "-sV", "-sC", "--open"],
        "full":    ["-T4", "-p-", "--open"],
        "os":      ["-T4", "-O", "-sV", "--open"],
        "stealth": ["-sS", "-T2", "--open"],
    }
    flags = profiles.get(profile, profiles["quick"])
    return run_streaming(["nmap"] + flags + [target])


@app.route("/scan/rustscan")
def scan_rustscan():
    target = request.args.get("target", "").strip()
    if not target:
        return Response("data: [ERROR] Kein Ziel angegeben\n\n", mimetype="text/event-stream")
    return run_streaming(["nmap", "-T4", "--open", "-p-", "--min-rate", "5000", target])


# ── WLAN Scanner ───────────────────────────────────────────────────────────────

@app.route("/scan/iw")
def scan_iw():
    iface = request.args.get("iface", "wlan0").strip()
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
    return run_streaming(["iw", "dev", iface, "scan"])


@app.route("/scan/iwlist")
def scan_iwlist():
    iface = request.args.get("iface", "wlan0").strip()
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
    return run_streaming(["iwlist", iface, "scanning"])


@app.route("/scan/airodump")
def scan_airodump():
    iface = request.args.get("iface", "wlan0mon").strip()
    return run_streaming([
        "airodump-ng", "--output-format", "csv",
        "--write-interval", "1", "--berlin", "10", iface
    ])


@app.route("/interfaces")
def get_interfaces():
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        ifaces = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                name = line.split()[-1]
                phy = subprocess.run(["iw", "phy"], capture_output=True, text=True)
                monitor = "monitor" in phy.stdout.lower()
                ifaces.append({"name": name, "monitor": monitor})
        return jsonify({"interfaces": ifaces})
    except Exception as e:
        return jsonify({"interfaces": [], "error": str(e)})


# ── Wordlists ──────────────────────────────────────────────────────────────────

def _wordlist_dir(category):
    """Return (bundled_dir, custom_dir) for a category."""
    return (
        os.path.join(WORDLIST_BASE, category),
        os.path.join(CUSTOM_BASE, category),
    )


def _safe_wordlist_path(category, filename):
    """Resolve path, checking custom dir first, then bundled. Prevents traversal."""
    if not filename or "/" in filename or "\\" in filename or not filename.endswith(".txt"):
        return None
    bundled, custom = _wordlist_dir(category)
    for base in (custom, bundled):
        full = os.path.realpath(os.path.join(base, filename))
        if os.path.isfile(full) and full.startswith(os.path.realpath(base) + os.sep):
            return full
    return None


def _count_lines(path):
    try:
        return sum(1 for _ in open(path, errors="ignore"))
    except Exception:
        return 0


@app.route("/wordlists")
def list_wordlists():
    """Return available wordlists (bundled + custom) with metadata."""
    def scan(category):
        bundled_dir, custom_dir = _wordlist_dir(category)
        seen = {}

        # Bundled lists
        if os.path.isdir(bundled_dir):
            for f in os.listdir(bundled_dir):
                if f.endswith(".txt"):
                    p = os.path.join(bundled_dir, f)
                    seen[f] = {
                        "name": f,
                        "lines": _count_lines(p),
                        "size": os.path.getsize(p),
                        "custom": False,
                        "updatable": f in WORDLIST_SOURCES.get(category, {}),
                    }

        # Custom lists (override bundled if same name)
        if os.path.isdir(custom_dir):
            for f in os.listdir(custom_dir):
                if f.endswith(".txt"):
                    p = os.path.join(custom_dir, f)
                    seen[f] = {
                        "name": f,
                        "lines": _count_lines(p),
                        "size": os.path.getsize(p),
                        "custom": True,
                        "updatable": f in WORDLIST_SOURCES.get(category, {}),
                    }

        return sorted(seen.values(), key=lambda x: x["lines"])

    return jsonify({
        "usernames": scan("usernames"),
        "passwords": scan("passwords"),
        "webpaths":  scan("webpaths"),
        "hints": PROTO_HINTS,
    })


@app.route("/wordlists/upload", methods=["POST"])
def upload_wordlist():
    """Upload a custom wordlist .txt file (multipart or URL fetch)."""
    category = request.args.get("category", "").strip()
    if category not in ("usernames", "passwords"):
        return jsonify({"error": "Ungültige Kategorie"}), 400

    _, custom_dir = _wordlist_dir(category)
    os.makedirs(custom_dir, exist_ok=True)

    # ── File upload ──
    if "file" in request.files:
        f = request.files["file"]
        fname = re.sub(r"[^\w\-\.]", "_", f.filename or "custom.txt")
        if not fname.endswith(".txt"):
            fname += ".txt"
        dest = os.path.join(custom_dir, fname)
        content = f.read(10 * 1024 * 1024)  # 10 MB limit
        if len(content) >= 10 * 1024 * 1024:
            return jsonify({"error": "Datei zu groß (max 10 MB)"}), 413
        with open(dest, "wb") as out:
            out.write(content)
        lines = _count_lines(dest)
        return jsonify({"ok": True, "name": fname, "lines": lines, "custom": True})

    # ── URL fetch ──
    url = (request.json or {}).get("url", "").strip() if request.is_json else request.form.get("url", "").strip()
    if url:
        if not url.startswith(("http://", "https://")):
            return jsonify({"error": "Nur http/https URLs erlaubt"}), 400
        fname = re.sub(r"[^\w\-\.]", "_", url.split("/")[-1] or "custom.txt")
        if not fname.endswith(".txt"):
            fname += ".txt"
        dest = os.path.join(custom_dir, fname)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ReconAddon/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read(10 * 1024 * 1024)
            with open(dest, "wb") as out:
                out.write(content)
            lines = _count_lines(dest)
            return jsonify({"ok": True, "name": fname, "lines": lines, "custom": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "Keine Datei oder URL angegeben"}), 400


@app.route("/wordlists/delete", methods=["POST"])
def delete_wordlist():
    """Delete a custom wordlist file."""
    category = request.args.get("category", "").strip()
    filename = request.args.get("filename", "").strip()
    if category not in ("usernames", "passwords"):
        return jsonify({"error": "Ungültige Kategorie"})
    if not filename or "/" in filename or "\\" in filename:
        return jsonify({"error": "Ungültiger Dateiname"})
    _, custom_dir = _wordlist_dir(category)
    filepath = os.path.realpath(os.path.join(custom_dir, filename))
    if not filepath.startswith(os.path.realpath(custom_dir) + os.sep):
        return jsonify({"error": "Zugriff verweigert"})
    if not os.path.isfile(filepath):
        return jsonify({"error": "Datei nicht gefunden"})
    os.remove(filepath)
    return jsonify({"ok": True, "deleted": filename})


@app.route("/wordlists/check-updates")
def check_wordlist_updates():
    """Compare local file sizes with GitHub raw Content-Length."""
    results = {}
    for category, files in WORDLIST_SOURCES.items():
        bundled_dir, custom_dir = _wordlist_dir(category)
        for fname, gh_path in files.items():
            # Prefer custom over bundled
            local = None
            for d in (custom_dir, bundled_dir):
                p = os.path.join(d, fname)
                if os.path.isfile(p):
                    local = p
                    break
            if not local:
                continue
            local_size = os.path.getsize(local)
            url = SECLISTS_RAW + gh_path
            try:
                req = urllib.request.Request(url, method="HEAD",
                                              headers={"User-Agent": "ReconAddon/1.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    remote_size = int(resp.headers.get("Content-Length", -1))
                results[fname] = {
                    "update_available": remote_size > 0 and remote_size != local_size,
                    "local_size": local_size,
                    "remote_size": remote_size,
                }
            except Exception as e:
                results[fname] = {"update_available": None, "error": str(e)}
    return jsonify(results)


@app.route("/wordlists/update", methods=["POST"])
def update_wordlist():
    """Download the latest version of a bundled list from SecLists."""
    data = request.get_json(force=True, silent=True) or {}
    category = data.get("category", "").strip()
    fname    = data.get("file", "").strip()

    if category not in WORDLIST_SOURCES or fname not in WORDLIST_SOURCES[category]:
        return jsonify({"error": "Nicht in Quellliste"}), 404

    _, custom_dir = _wordlist_dir(category)
    os.makedirs(custom_dir, exist_ok=True)
    dest = os.path.join(custom_dir, fname)
    url  = SECLISTS_RAW + WORDLIST_SOURCES[category][fname]

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconAddon/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read(50 * 1024 * 1024)  # 50 MB max
        with open(dest, "wb") as out:
            out.write(content)
        lines = _count_lines(dest)
        return jsonify({"ok": True, "name": fname, "lines": lines})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Web Tools ──────────────────────────────────────────────────────────────────

@app.route("/scan/nikto")
def scan_nikto():
    target = request.args.get("target", "").strip()
    port   = request.args.get("port",   "").strip()
    ssl    = request.args.get("ssl",    "").strip()
    if not target:
        return Response("data: [ERROR] Kein Ziel angegeben\n\n", mimetype="text/event-stream")
    cmd = ["nikto", "-h", target, "-nointeractive"]
    if port:
        cmd += ["-p", port]
    if ssl == "1":
        cmd += ["-ssl"]
    return run_streaming(cmd)


@app.route("/scan/ffuf")
def scan_ffuf():
    target  = request.args.get("target",  "").strip()   # full URL with FUZZ placeholder
    wl      = request.args.get("wordlist","common.txt").strip()
    threads = request.args.get("threads", "40").strip()
    ext     = request.args.get("ext",     "").strip()   # optional extensions, comma-separated

    if not target:
        return Response("data: [ERROR] Kein Ziel angegeben\n\n", mimetype="text/event-stream")
    if "FUZZ" not in target:
        target = target.rstrip("/") + "/FUZZ"

    wl_path = _safe_wordlist_path("webpaths", wl)
    if not wl_path:
        return Response("data: [ERROR] Ungültige Wordlist\n\n", mimetype="text/event-stream")

    try:
        t = str(max(1, min(200, int(threads))))
    except Exception:
        t = "40"

    cmd = ["ffuf", "-u", target, "-w", wl_path, "-t", t, "-v", "-noninteractive"]
    if ext:
        cmd += ["-e", ext]
    return run_streaming(cmd)


# ── Login Form Auto-Detect ─────────────────────────────────────────────────────

@app.route("/scan/detect-login")
def detect_login():
    from html.parser import HTMLParser
    from urllib.parse import urljoin, urlparse, urlencode

    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "Kein Ziel angegeben"})
    if not target.startswith("http"):
        target = "http://" + target

    class _FormParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms = []
            self._form = None
            self._inputs = []
        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self._form = a
                self._inputs = []
            elif tag == "input" and self._form is not None:
                self._inputs.append(a)
        def handle_endtag(self, tag):
            if tag == "form" and self._form is not None:
                self.forms.append({
                    "action": self._form.get("action", ""),
                    "method": self._form.get("method", "get").lower(),
                    "inputs": self._inputs[:]
                })
                self._form = None

    try:
        # Fetch target page with curl (-L follows redirects to find login page)
        r = subprocess.run(
            ["curl", "-s", "-L", "--max-time", "10",
             "-A", "Mozilla/5.0 (compatible; Recon/1.0)", target],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0 or not r.stdout.strip():
            return jsonify({"error": "Seite nicht erreichbar"})
        html = r.stdout

        # Also try /login if no form on main page
        pages_to_try = [html]
        p0 = _FormParser()
        p0.feed(html)
        has_login_form = any(
            f["method"] == "post" and
            any(i.get("type", "").lower() == "password" for i in f["inputs"])
            for f in p0.forms
        )
        if not has_login_form:
            for path in ["/login", "/login.jsp", "/signin", "/auth/login"]:
                try:
                    r2 = subprocess.run(
                        ["curl", "-s", "-L", "--max-time", "5",
                         "-A", "Mozilla/5.0", target.rstrip("/") + path],
                        capture_output=True, text=True, timeout=8
                    )
                    if r2.returncode == 0 and r2.stdout.strip():
                        pages_to_try.append(r2.stdout)
                except Exception:
                    pass

        # Parse all fetched pages to find a login form
        login_form = None
        for page_html in pages_to_try:
            p = _FormParser()
            p.feed(page_html)
            login_form = next((
                f for f in p.forms
                if f["method"] == "post" and
                any(i.get("type", "").lower() == "password" for i in f["inputs"])
            ), None)
            if login_form:
                break
        if not login_form:
            return jsonify({"error": "Kein Login-Formular gefunden. Prüfe ob die URL korrekt ist."})

        # Extract field names
        user_field = pass_field = None
        extra = {}
        for inp in login_form["inputs"]:
            t = inp.get("type", "text").lower()
            n = inp.get("name", "")
            if not n:
                continue
            if t == "password":
                pass_field = n
            elif t in ("text", "email") and not user_field:
                user_field = n
            elif t in ("hidden", "submit") and inp.get("value"):
                extra[n] = inp["value"]

        # Resolve action URL
        action_raw = login_form["action"] or "/"
        action_path = urlparse(urljoin(target + "/", action_raw)).path

        # Test dummy login with curl (no redirect follow) to detect failure pattern
        post_data = {user_field or "user": "dummyxyz", pass_field or "pass": "dummyxyz"}
        post_data.update(extra)
        action_url = target.rstrip("/") + action_path

        r3 = subprocess.run(
            ["curl", "-s", "-i", "--max-time", "10",
             "-A", "Mozilla/5.0",
             "-X", "POST", "-d", urlencode(post_data),
             action_url],
            capture_output=True, text=True, timeout=15
        )
        resp_output = r3.stdout

        # Split headers and body
        sep = resp_output.find("\r\n\r\n")
        if sep == -1:
            sep = resp_output.find("\n\n")
        headers_str = resp_output[:sep] if sep > 0 else ""
        fail_body = resp_output[sep + 4:] if sep > 0 else resp_output

        # Extract Location header and status
        fail_location = ""
        loc_m = re.search(r"Location:\s*(\S+)", headers_str, re.IGNORECASE)
        if loc_m:
            fail_location = loc_m.group(1)
        status_m = re.search(r"HTTP/\S+\s+(\d+)", headers_str)
        status_code = int(status_m.group(1)) if status_m else 200

        # Determine detection mode
        detect_mode = "F"
        detect_string = ""
        redirect_based = status_code in (301, 302, 303, 307, 308) and bool(fail_location)

        if redirect_based:
            # For redirect-based auth, Hydra checks the raw 302 response
            # (including headers). We use F= with something from the FAILURE
            # response headers, or S= with something unique to SUCCESS headers.
            #
            # Strategy: the failed 302 Location header (e.g. "login.jsp")
            # is unique to failure. Use F= with that Location value.
            # Hydra sees the full response including headers, so
            # F=login.jsp will match "Location: login.jsp" in the failure response.
            fail_loc_file = urlparse(fail_location).path.split("/")[-1]
            if fail_loc_file:
                detect_string = fail_loc_file
            else:
                detect_string = fail_location
        else:
            for kw in ["incorrect", "invalid", "wrong", "failed", "denied",
                        "error", "ungültig", "falsch"]:
                if kw.lower() in fail_body.lower():
                    detect_string = kw
                    break

        # Identify CSRF field name
        csrf_field = ""
        for name in extra:
            if any(tok in name.lower() for tok in ["csrf", "token", "_token", "xsrf"]):
                csrf_field = name
                break

        return jsonify({
            "action": action_path,
            "user_field": user_field or "",
            "pass_field": pass_field or "",
            "extra_fields": extra,
            "csrf_field": csrf_field,
            "detect_mode": detect_mode,
            "detect_string": detect_string,
            "redirect_based": redirect_based,
            "fail_location": fail_location,
        })

    except Exception as e:
        return jsonify({"error": f"Auto-Detect Fehler: {e}"})


# ── CSRF Brute Force ──────────────────────────────────────────────────────────

@app.route("/scan/brute-csrf")
def scan_brute_csrf():
    target    = request.args.get("target",      "").strip()
    login_url = request.args.get("login_url",   "/login").strip()
    user_field= request.args.get("user_field",  "username").strip()
    pass_field= request.args.get("pass_field",  "password").strip()
    csrf_field= request.args.get("csrf_field",  "").strip()
    detect_mode = request.args.get("detect_mode", "F").strip()
    detect_str  = request.args.get("detect_str",  "incorrect").strip()
    extra_fields= request.args.get("extra_fields","").strip()
    port      = request.args.get("port",        "").strip()
    tasks     = request.args.get("tasks",       "1").strip()
    wait_ms   = request.args.get("wait_ms",     "0").strip()
    userlist  = request.args.get("userlist",    "").strip()
    passlist  = request.args.get("passlist",    "").strip()
    usernames = request.args.get("usernames",   "").strip()
    passwords = request.args.get("passwords",   "").strip()

    if not target:
        return Response("data: [ERROR] Kein Ziel angegeben\n\n", mimetype="text/event-stream")

    # Determine if HTTPS
    is_https = target.startswith("https") or request.args.get("protocol", "").startswith("https")
    if not target.startswith("http"):
        target = ("https://" if is_https else "http://") + target

    cmd = ["python3", os.path.join(os.path.dirname(__file__), "csrf_brute.py"),
           "--target", target,
           "--login-url", login_url,
           "--user-field", user_field,
           "--pass-field", pass_field,
           "--detect-mode", detect_mode,
           "--detect-str", detect_str,
           "--tasks", str(max(1, min(8, int(tasks) if tasks.isdigit() else 1))),
           "--wait-ms", wait_ms if wait_ms.isdigit() else "0"]

    if csrf_field:
        cmd += ["--csrf-field", csrf_field]
    if extra_fields:
        cmd += ["--extra-fields", extra_fields]
    if port:
        cmd += ["--port", port]
    if is_https:
        cmd += ["--no-verify-ssl"]

    # Username source
    if userlist:
        src = _safe_wordlist_path("usernames", userlist)
        if not src:
            return Response("data: [ERROR] Ungültige Username-Liste\n\n", mimetype="text/event-stream")
        filtered, count = _filter_userlist_file(src)
        if filtered:
            cmd += ["--userfile", filtered]
        else:
            return Response("data: [ERROR] Liste enthält keine gültigen Einträge\n\n", mimetype="text/event-stream")
    elif usernames:
        cmd += ["--users", usernames]
    else:
        cmd += ["--users", "admin"]

    # Password source
    if passlist:
        pw_path = _safe_wordlist_path("passwords", passlist)
        if not pw_path:
            return Response("data: [ERROR] Ungültige Passwort-Liste\n\n", mimetype="text/event-stream")
        cmd += ["--passfile", pw_path]
    elif passwords:
        cmd += ["--passwords", passwords]
    else:
        return Response("data: [ERROR] Kein Passwort / keine Passwortliste\n\n", mimetype="text/event-stream")

    return run_streaming(cmd)


# ── Brute Force ────────────────────────────────────────────────────────────────

def _filter_userlist_file(src_path):
    """Return a cleaned temp file with only valid username entries."""
    valid = []
    with open(src_path, errors="ignore") as f:
        for line in f:
            u = line.strip()
            if u and _VALID_USER_RE.match(u):
                valid.append(u)
    if not valid:
        return None, 0
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="recon_users_")
    tf.write("\n".join(valid) + "\n")
    tf.close()
    return tf.name, len(valid)


@app.route("/scan/brute")
def scan_brute():
    target   = request.args.get("target",   "").strip()
    protocol = request.args.get("protocol", "ssh").strip()
    port     = request.args.get("port",     "").strip()
    path     = request.args.get("path",     "/").strip()  # for http-get/https-get
    # wait_ms: milliseconds from UI → convert to seconds for hydra
    wait_ms  = request.args.get("wait_ms",  "").strip()
    tasks    = request.args.get("tasks",    "").strip()
    userlist = request.args.get("userlist", "").strip()
    passlist = request.args.get("passlist", "").strip()
    usernames = request.args.get("usernames", "").strip()
    passwords = request.args.get("passwords", "").strip()

    if not target:
        return Response("data: [ERROR] Kein Ziel angegeben\n\n", mimetype="text/event-stream")

    # ── Resolve tasks & wait ──────────────────────────────────────
    hint = PROTO_HINTS.get(protocol, {"tasks": 4, "wait_ms": 0})
    default_tasks = hint["tasks"]
    default_wait_s = hint["wait_ms"] // 1000

    try:
        t = str(max(1, min(16, int(tasks)))) if tasks.isdigit() else str(default_tasks)
    except Exception:
        t = str(default_tasks)

    try:
        w = str(int(wait_ms) // 1000) if wait_ms.isdigit() else str(default_wait_s)
    except Exception:
        w = str(default_wait_s)

    tmp_files = []

    try:
        cmd = ["hydra", "-t", t, "-W", w, "-V"]

        # ── Username source ───────────────────────────────────────
        if userlist:
            src = _safe_wordlist_path("usernames", userlist)
            if not src:
                return Response("data: [ERROR] Ungültige Username-Liste\n\n", mimetype="text/event-stream")
            filtered, count = _filter_userlist_file(src)
            if not filtered:
                return Response("data: [ERROR] Liste enthält keine gültigen Einträge\n\n", mimetype="text/event-stream")
            tmp_files.append(filtered)
            cmd += ["-L", filtered]
        else:
            user_list = [u.strip() for u in usernames.split(",")
                         if u.strip() and _VALID_USER_RE.match(u.strip())] or ["admin"]
            if len(user_list) == 1:
                cmd += ["-l", user_list[0]]
            else:
                uf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="recon_")
                uf.write("\n".join(user_list))
                uf.close()
                tmp_files.append(uf.name)
                cmd += ["-L", uf.name]

        # ── Password source ───────────────────────────────────────
        if passlist:
            pw_path = _safe_wordlist_path("passwords", passlist)
            if not pw_path:
                return Response("data: [ERROR] Ungültige Passwort-Liste\n\n", mimetype="text/event-stream")
            cmd += ["-P", pw_path]
        elif passwords:
            pass_list = [p.strip() for p in passwords.split(",") if p.strip()]
            if not pass_list:
                return Response("data: [ERROR] Kein Passwort angegeben\n\n", mimetype="text/event-stream")
            if len(pass_list) == 1:
                cmd += ["-p", pass_list[0]]
            else:
                pf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="recon_")
                pf.write("\n".join(pass_list))
                pf.close()
                tmp_files.append(pf.name)
                cmd += ["-P", pf.name]
        else:
            return Response("data: [ERROR] Kein Passwort / keine Passwortliste angegeben\n\n", mimetype="text/event-stream")

        if port:
            cmd += ["-s", port]
        # Auto-upgrade http-get → http-post-form when path contains POST form syntax
        if protocol == "http-get" and ("^USER^" in path or "^PASS^" in path):
            protocol = "http-post-form"
        elif protocol == "https-get" and ("^USER^" in path or "^PASS^" in path):
            protocol = "https-post-form"
        cmd += [target, protocol]
        # HTTP/HTTPS require a path as module-specific option
        if protocol in ("http-get", "https-get", "http-post-form", "https-post-form"):
            cmd.append(path or "/")

    except Exception as e:
        for f in tmp_files:
            try: os.unlink(f)
            except: pass
        return Response(f"data: [ERROR] {e}\n\n", mimetype="text/event-stream")

    def generate():
        import select as sel
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            fd = process.stdout.fileno()
            while True:
                ready, _, _ = sel.select([fd], [], [], 15)
                if ready:
                    line = process.stdout.readline()
                    if line == "":
                        break
                    yield f"data: {line.rstrip()}\n\n"
                else:
                    yield ": keep-alive\n\n"
                if process.poll() is not None:
                    for line in process.stdout:
                        yield f"data: {line.rstrip()}\n\n"
                    break
            process.wait()
            yield f"data: [DONE] Exit code: {process.returncode}\n\n"
        except FileNotFoundError:
            yield "data: [ERROR] hydra nicht gefunden – bitte Addon neu bauen\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"
        finally:
            for f in tmp_files:
                try: os.unlink(f)
                except: pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=INGRESS_PORT, debug=False, threaded=True)
