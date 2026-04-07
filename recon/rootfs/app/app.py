#!/usr/bin/env python3
import subprocess
import shutil
import os
from flask import Flask, render_template, request, Response, stream_with_context, jsonify

app = Flask(__name__)

INGRESS_PATH = os.environ.get("INGRESS_PATH", "")
INGRESS_PORT = int(os.environ.get("INGRESS_PORT", 8765))


def run_streaming(cmd):
    """Run a command and stream output line by line via SSE."""
    def generate():
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in process.stdout:
                yield f"data: {line.rstrip()}\n\n"
            process.wait()
            yield f"data: [DONE] Exit code: {process.returncode}\n\n"
        except FileNotFoundError:
            yield f"data: [ERROR] Befehl nicht gefunden: {cmd[0]}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {str(e)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
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
        "full":    ["-T4", "-p-", "--open"],
        "service": ["-T4", "-sV", "-sC", "--open"],
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
    if not shutil.which("rustscan"):
        return Response("data: [ERROR] RustScan nicht installiert\n\n", mimetype="text/event-stream")
    return run_streaming(["rustscan", "-a", target, "--", "-sV", "--open"])


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=INGRESS_PORT, debug=False)
