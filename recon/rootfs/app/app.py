#!/usr/bin/env python3
import subprocess
import shutil
import os
import re
import tempfile
from flask import Flask, render_template, request, Response, stream_with_context, jsonify

# Valid username chars for SSH/FTP/common services
_VALID_USER_RE = re.compile(r'^[a-zA-Z0-9_\-\.@]{1,64}$')

app = Flask(__name__)

INGRESS_PATH = os.environ.get("INGRESS_PATH", "")
INGRESS_PORT = int(os.environ.get("INGRESS_PORT", 8765))

WORDLIST_BASE = os.path.join(os.path.dirname(__file__), "wordlists")


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
                # Wait up to 15s for output, then send SSE keepalive comment
                ready, _, _ = sel.select([fd], [], [], 15)
                if ready:
                    line = process.stdout.readline()
                    if line == '':
                        break  # EOF
                    yield f"data: {line.rstrip()}\n\n"
                else:
                    # Keep connection alive during long scans
                    yield ": keep-alive\n\n"

                if process.poll() is not None:
                    # Drain remaining output after process exits
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
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )


@app.route("/")
def index():
    return render_template(
        "index.html",
        ingress_path=INGRESS_PATH,
        has_rustscan=shutil.which("rustscan") is not None,
        has_nmap=shutil.which("nmap") is not None,
        has_iw=shutil.which("iw") is not None,
        has_iwlist=shutil.which("iwlist") is not None,
        has_airodump=shutil.which("airodump-ng") is not None,
        has_hydra=shutil.which("hydra") is not None,
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
    # RustScan not available on aarch64/Alpine - use fast nmap instead
    target = request.args.get("target", "").strip()
    if not target:
        return Response("data: [ERROR] Kein Ziel angegeben\n\n", mimetype="text/event-stream")
    # Fast full-port scan: alle 65535 Ports mit hoher Rate
    return run_streaming(["nmap", "-T4", "--open", "-p-", "--min-rate", "5000", target])


# ── WLAN Scanner ───────────────────────────────────────────────────────────────

@app.route("/scan/iw")
def scan_iw():
    iface = request.args.get("iface", "wlan0").strip()
    # Bring interface up first
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
    """List available wireless interfaces and their monitor mode capability."""
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        ifaces = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                name = line.split()[-1]
                # Check if monitor mode is supported
                phy = subprocess.run(["iw", "phy"], capture_output=True, text=True)
                monitor = "monitor" in phy.stdout.lower()
                ifaces.append({"name": name, "monitor": monitor})
        return jsonify({"interfaces": ifaces})
    except Exception as e:
        return jsonify({"interfaces": [], "error": str(e)})


# ── Wordlists ──────────────────────────────────────────────────────────────────

@app.route("/wordlists")
def list_wordlists():
    """Return available SecLists wordlists grouped by type."""
    def scan(subdir):
        path = os.path.join(WORDLIST_BASE, subdir)
        if not os.path.isdir(path):
            return []
        return sorted([
            {"name": f, "lines": sum(1 for _ in open(os.path.join(path, f), errors="ignore"))}
            for f in os.listdir(path) if f.endswith(".txt")
        ], key=lambda x: x["lines"])

    return jsonify({
        "usernames": scan("usernames"),
        "passwords": scan("passwords"),
    })


# ── Brute Force ────────────────────────────────────────────────────────────────

def _safe_wordlist_path(subdir, filename):
    """Resolve and validate a wordlist path to prevent path traversal."""
    if not filename or "/" in filename or "\\" in filename or not filename.endswith(".txt"):
        return None
    full = os.path.realpath(os.path.join(WORDLIST_BASE, subdir, filename))
    base = os.path.realpath(os.path.join(WORDLIST_BASE, subdir))
    if not full.startswith(base + os.sep):
        return None
    return full if os.path.isfile(full) else None


def _filter_userlist_file(src_path):
    """Return a cleaned temp file with only valid username entries."""
    valid = []
    with open(src_path, errors="ignore") as f:
        for line in f:
            u = line.strip()
            if u and _VALID_USER_RE.match(u):
                valid.append(u)
    if not valid:
        return None, []
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="recon_users_")
    tf.write("\n".join(valid) + "\n")
    tf.close()
    return tf.name, valid


@app.route("/scan/brute")
def scan_brute():
    target    = request.args.get("target",    "").strip()
    protocol  = request.args.get("protocol",  "ssh").strip()
    port      = request.args.get("port",      "").strip()
    tasks     = request.args.get("tasks",     "").strip()   # parallel hydra tasks
    wait      = request.args.get("wait",      "").strip()   # seconds between retries
    # Wordlist file names (from /app/wordlists/)
    userlist  = request.args.get("userlist",  "").strip()
    passlist  = request.args.get("passlist",  "").strip()
    # Fallback: manual comma-separated values
    usernames = request.args.get("usernames", "").strip()
    passwords = request.args.get("passwords", "").strip()

    if not target:
        return Response("data: [ERROR] Kein Ziel angegeben\n\n", mimetype="text/event-stream")

    # Protocol defaults for tasks/wait (SSH is restrictive)
    ssh_like = protocol in ("ssh", "rdp", "smb")
    default_tasks = "1" if ssh_like else "4"
    default_wait  = "3" if ssh_like else "0"

    t = tasks if tasks.isdigit() and 1 <= int(tasks) <= 16 else default_tasks
    w = wait  if wait.isdigit()  and 0 <= int(wait)  <= 30 else default_wait

    tmp_files = []

    try:
        cmd = ["hydra", "-t", t, "-W", w, "-V"]

        # ── Username source ───────────────────────────────────────
        if userlist:
            src = _safe_wordlist_path("usernames", userlist)
            if not src:
                return Response("data: [ERROR] Ungültige Username-Liste\n\n", mimetype="text/event-stream")
            filtered, valid = _filter_userlist_file(src)
            if not filtered:
                return Response("data: [ERROR] Liste enthält keine gültigen Einträge\n\n", mimetype="text/event-stream")
            tmp_files.append(filtered)
            cmd += ["-L", filtered]
            # Echo stats as first SSE line later (done via initial appendLine in JS)
        else:
            user_list = [u.strip() for u in usernames.split(",") if u.strip() and _VALID_USER_RE.match(u.strip())] or ["admin"]
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
            path = _safe_wordlist_path("passwords", passlist)
            if not path:
                return Response("data: [ERROR] Ungültige Passwort-Liste\n\n", mimetype="text/event-stream")
            cmd += ["-P", path]
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

        cmd += [target, protocol]

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
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=INGRESS_PORT, debug=False, threaded=True)
