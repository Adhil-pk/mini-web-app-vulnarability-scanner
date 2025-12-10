#!/usr/bin/env python3
"""
app.py - Mini Web Application Vulnerability Scanner with Flask UI
Educational use only. Scan only targets you own or have permission to test.

Dependencies:
    pip install flask requests beautifulsoup4
Run:
    python app.py
"""

import re
import sqlite3
import threading
import time
import random
import string
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode
from collections import deque

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, redirect, url_for, render_template_string, g

# ---------- Config ----------
APP_HOST = "0.0.0.0"
APP_PORT = 5000
USER_AGENT = "mini-wav-scanner/1.0 (edu)"
CRAWL_DELAY = 0.3
TIMEOUT = 12
MAX_PAGES = 60

DB_PATH = "scans.db"

XSS_PAYLOAD = "<!--SCAN{}-->"  # benign token-style payload (non-executable)
SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "'; --", "' OR 1=1 -- "]
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"ora-\d{5}",
    r"syntax error.*mysql",
    r"sqlstate",
    r"mysql_fetch",
    r"pg_query\(",
]
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]
CSRF_TOKEN_NAMES = ["csrf", "csrf_token", "_csrf", "token", "authenticity_token"]

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

app = Flask(__name__)

# ---------- DB helpers ----------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        g._db = db
    return db

def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        started_at TIMESTAMP,
        finished_at TIMESTAMP
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        url TEXT,
        issue_type TEXT,
        severity TEXT,
        evidence TEXT,
        extra TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )
    """)
    db.commit()
    db.close()

@app.teardown_appcontext
def close_db(error):
    db = getattr(g, "_db", None)
    if db:
        db.close()

def log_scan_start(target):
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO scans (target, started_at) VALUES (?, datetime('now'))", (target,))
    db.commit()
    return cur.lastrowid

def log_scan_finish(scan_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE scans SET finished_at = datetime('now') WHERE id = ?", (scan_id,))
    db.commit()

def log_finding(scan_id, url, issue_type, severity, evidence, extra=""):
    db = get_db()
    db.execute("INSERT INTO findings (scan_id, url, issue_type, severity, evidence, extra) VALUES (?, ?, ?, ?, ?, ?)",
               (scan_id, url, issue_type, severity, evidence, extra))
    db.commit()

# ---------- Scanning helpers ----------
def random_token(n=8):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

def same_domain(base, url):
    try:
        return urlparse(base).netloc == urlparse(url).netloc
    except:
        return False

def get_links(html, base):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        u = urljoin(base, a["href"])
        if u.startswith("http"):
            links.add(u.split("#")[0])
    return links

def find_forms(html, base):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        url = urljoin(base, action)
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            typ = inp.get("type", "text")
            inputs.append({"name": name, "type": typ, "value": inp.get("value", "")})
        forms.append({"url": url, "method": method, "inputs": inputs})
    return forms

def check_headers(resp):
    missing = []
    present = {}
    for h in SECURITY_HEADERS:
        if h in resp.headers:
            present[h] = resp.headers[h]
        else:
            missing.append(h)
    return present, missing

def fingerprint_sql_errors(body):
    tl = (body or "").lower()
    for p in SQL_ERROR_PATTERNS:
        if re.search(p, tl):
            return True, p
    return False, None

# For GET endpoints we will inject token into a parameter
def inject_get_and_check(url, token):
    parsed = requests.utils.urlparse(url)
    qs = dict(parse_qsl(parsed.query))
    if not qs:
        qs["_scan"] = token
    else:
        first_key = next(iter(qs))
        qs[first_key] = token
    new_q = urlencode(qs)
    new_url = parsed._replace(query=new_q).geturl()
    try:
        r = session.get(new_url, timeout=TIMEOUT)
    except Exception as e:
        return {"error": str(e)}
    body = r.text or ""
    findings = {
        "url": new_url,
        "status": r.status_code,
        "reflected": token in body,
        "sql_error": fingerprint_sql_errors(body)[0],
        "headers_present": dict(r.headers),
        "headers_missing": [h for h in SECURITY_HEADERS if h not in r.headers]
    }
    return findings

def inject_form_and_check(form, token):
    data = {}
    for inp in form["inputs"]:
        n = inp["name"]
        t = inp["type"]
        if t in ["text", "search", "email", "textarea", "password", "url"]:
            data[n] = XSS_PAYLOAD.format(token)
        else:
            data[n] = inp.get("value", "1")
    try:
        if form["method"] == "post":
            r = session.post(form["url"], data=data, timeout=TIMEOUT)
        else:
            r = session.get(form["url"], params=data, timeout=TIMEOUT)
    except Exception as e:
        return {"error": str(e)}
    body = r.text or ""
    findings = {
        "form_url": form["url"],
        "method": form["method"],
        "status": r.status_code,
        "reflected": (XSS_PAYLOAD.format(token) in body),
        "sql_error": fingerprint_sql_errors(body)[0],
        "headers_present": dict(r.headers),
        "headers_missing": [h for h in SECURITY_HEADERS if h not in r.headers]
    }
    return findings

def basic_csrf_check(form):
    # If a form's inputs lack hidden CSRF token by name pattern -> potential missing CSRF
    hidden_names = [inp["name"].lower() for inp in form["inputs"]]
    for t in CSRF_TOKEN_NAMES:
        if any(t in n for n in hidden_names):
            return False  # appears to have token
    # If method is GET -> not CSRF-protected normally
    if form["method"].lower() == "get":
        return True  # GET forms could be stateful and wrong, flag for review
    return True

# ---------- Main scan routine ----------
def crawl_and_scan(start_url, scan_id=None, max_pages=MAX_PAGES):
    start_url = start_url.rstrip("/")
    visited = set()
    q = deque([start_url])
    token = random_token()
    pages_visited = 0

    while q and pages_visited < max_pages:
        url = q.popleft()
        if url in visited:
            continue
        visited.add(url)
        pages_visited += 1
        try:
            r = session.get(url, timeout=TIMEOUT)
        except Exception as e:
            log_finding(scan_id, url, "fetch-error", "low", str(e))
            continue

        # header checks
        present, missing = check_headers(r)
        if missing:
            evidence = "Missing headers: " + ", ".join(missing)
            log_finding(scan_id, url, "missing-security-headers", "medium", evidence, extra=str(missing))

        # collect same-domain links
        links = get_links(r.text, url)
        for link in links:
            if same_domain(start_url, link) and link not in visited:
                q.append(link)

        # GET param injection check
        if urlparse(url).query:
            res = inject_get_and_check(url, token)
            if res.get("error"):
                log_finding(scan_id, url, "get-injection-error", "low", res["error"])
            else:
                if res["reflected"]:
                    evidence = f"Injected token reflected in response at {res['url']}"
                    log_finding(scan_id, url, "reflected-input (GET)", "high", evidence)
                if res["sql_error"]:
                    evidence = f"SQL error fingerprint found in GET response at {res['url']}"
                    log_finding(scan_id, url, "sql-error-fingerprint (GET)", "critical", evidence)

                if res["headers_missing"]:
                    # already logged page-level header misses, but add an entry pointing to the GET
                    log_finding(scan_id, url, "missing-security-headers (GET)", "medium",
                                "Missing headers: " + ", ".join(res["headers_missing"]))

        # forms
        forms = find_forms(r.text, url)
        for form in forms:
            # CSRF check
            if basic_csrf_check(form):
                # if no obvious token found, flag as potential CSRF missing
                evidence = f"Form at {form['url']} appears to be missing CSRF token names: {', '.join([i['name'] for i in form['inputs']])}"
                log_finding(scan_id, form['url'], "missing-csrf-token", "high", evidence)

            fres = inject_form_and_check(form, token)
            if fres.get("error"):
                log_finding(scan_id, form.get("url", url), "form-injection-error", "low", fres["error"])
            else:
                if fres["reflected"]:
                    evidence = f"Form injection token reflected in response of {fres['form_url']}"
                    log_finding(scan_id, fres['form_url'], "reflected-input (form)", "high", evidence)
                if fres["sql_error"]:
                    evidence = f"SQL error fingerprint found in form response at {fres['form_url']}"
                    log_finding(scan_id, fres['form_url'], "sql-error-fingerprint (form)", "critical", evidence)
        time.sleep(CRAWL_DELAY)

    log_scan_finish(scan_id)

# ---------- Flask UI ----------
HOME_TMPL = """
<!doctype html>
<html>
  <head>
    <title>Mini Web App Vulnerability Scanner</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="p-4">
    <div class="container">
      <h1>Mini Web App Vulnerability Scanner</h1>
      <p class="text-muted">Educational scanner: scan only systems you own or have permission to test.</p>

      <form method="post" action="/scan" class="row g-3 mb-4">
        <div class="col-md-8">
          <input required name="target" placeholder="https://example.com" class="form-control" />
        </div>
        <div class="col-md-2">
          <input type="number" name="max_pages" class="form-control" placeholder="Max pages" value="30" />
        </div>
        <div class="col-md-2">
          <button class="btn btn-primary w-100">Start Scan (blocking)</button>
        </div>
      </form>

      <h4>Previous Scans</h4>
      {% if scans %}
      <table class="table table-sm">
        <thead><tr><th>ID</th><th>Target</th><th>Started</th><th>Finished</th><th>Findings</th></tr></thead>
        <tbody>
          {% for s in scans %}
          <tr>
            <td>{{ s.id }}</td>
            <td>{{ s.target }}</td>
            <td>{{ s.started_at }}</td>
            <td>{{ s.finished_at or '---' }}</td>
            <td><a href="{{ url_for('view_scan', scan_id=s.id) }}" class="btn btn-sm btn-outline-secondary">View</a></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p>No scans yet.</p>
      {% endif %}

      <hr/>
      <p class="text-muted"><strong>Notes:</strong> This scanner uses simple reflection and fingerprint checks. It does not authenticate, does not execute JS, and is not a replacement for full tools like Burp, Nikto, or OWASP ZAP.</p>
    </div>
  </body>
</html>
"""

SCAN_TMPL = """
<!doctype html>
<html>
  <head>
    <title>Scan {{ scan_id }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="p-4">
    <div class="container">
      <h1>Scan Completed: ID {{ scan_id }}</h1>
      <p>Target: <strong>{{ target }}</strong></p>
      <p>Started: {{ started_at }} — Finished: {{ finished_at }}</p>

      <h4>Findings ({{ findings|length }})</h4>
      {% if findings %}
      <table class="table table-sm">
        <thead><tr><th>Type</th><th>URL</th><th>Severity</th><th>Evidence</th></tr></thead>
        <tbody>
        {% for f in findings %}
          <tr>
            <td>{{ f.issue_type }}</td>
            <td style="max-width:400px;word-break:break-word">{{ f.url }}</td>
            <td>{{ f.severity }}</td>
            <td><pre style="white-space:pre-wrap;max-width:400px">{{ f.evidence }}</pre></td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p>No findings recorded.</p>
      {% endif %}

      <p><a href="{{ url_for('home') }}" class="btn btn-secondary">Back</a></p>
    </div>
  </body>
</html>
"""

@app.route("/")
def home():
    db = get_db()
    cur = db.execute("SELECT id, target, started_at, finished_at FROM scans ORDER BY id DESC LIMIT 30")
    scans = cur.fetchall()
    return render_template_string(HOME_TMPL, scans=scans)

@app.route("/scan", methods=["POST"])
def scan_post():
    target = request.form.get("target")
    if not target:
        return "Target required", 400
    max_pages = int(request.form.get("max_pages") or MAX_PAGES)
    # normalization
    if not target.startswith("http"):
        target = "http://" + target
    # start scan synchronously (blocking) for simplicity (project requirement)
    scan_id = log_scan_start(target)
    # run scan (this will block until finished)
    crawl_and_scan(target, scan_id=scan_id, max_pages=max_pages)
    return redirect(url_for("view_scan", scan_id=scan_id))

@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    db = get_db()
    s = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not s:
        return "Scan not found", 404
    findings = db.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
    return render_template_string(SCAN_TMPL,
                                  scan_id=scan_id,
                                  target=s["target"],
                                  started_at=s["started_at"],
                                  finished_at=s["finished_at"],
                                  findings=findings)

if __name__ == "__main__":
    init_db()
    print("Starting Mini Web App Vulnerability Scanner at http://127.0.0.1:5000")
    app.run(host=APP_HOST, port=APP_PORT, debug=True)
