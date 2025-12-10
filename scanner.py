# scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag, urlparse
import sqlite3
import uuid
import time

USER_AGENT = "SafeScanner/1.0 (+your_email@example.com)"
HEADERS = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}

class Logger:
    def __init__(self, db="vuln_results.db"):
        self.conn = sqlite3.connect(db, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        c = self.conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                vuln_type TEXT,
                severity TEXT,
                evidence TEXT,
                detail TEXT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def log(self, url, vuln_type, severity, evidence, detail=""):
        c = self.conn.cursor()
        c.execute('INSERT INTO findings (url, vuln_type, severity, evidence, detail) VALUES (?,?,?,?,?)',
                  (url, vuln_type, severity, evidence, detail))
        self.conn.commit()

class SimpleScanner:
    def __init__(self, base_url, logger: Logger, max_pages=200):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(self.base_url).netloc
        self.visited = set()
        self.to_visit = [self.base_url]
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.max_pages = max_pages
        self.logger = logger

    def same_domain(self, url):
        parsed = urlparse(url)
        return parsed.netloc == "" or parsed.netloc == self.domain

    def crawl(self):
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.pop(0)
            url = urldefrag(url)[0]
            if url in self.visited:
                continue
            try:
                r = self.session.get(url, timeout=10)
            except Exception as e:
                print("Fetch error", url, e)
                self.visited.add(url)
                continue
            html = r.text
            self.visited.add(url)
            self._extract_links(url, html)
            forms = self._extract_forms(html, url)
            for form in forms:
                self.test_form(form)
            time.sleep(0.2)

    def _extract_links(self, base, html):
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = urljoin(base, a["href"])
            href = urldefrag(href)[0]
            if self.same_domain(href) and href not in self.visited:
                self.to_visit.append(href)

    def _extract_forms(self, html, url):
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for f in soup.find_all("form"):
            form = {
                "action": urljoin(url, f.get("action") or ""),
                "method": f.get("method", "get").lower(),
                "inputs": []
            }
            for inp in f.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                itype = inp.get("type", "text")
                value = inp.get("value", "")
                if name:
                    form["inputs"].append({"name": name, "type": itype, "value": value})
            forms.append(form)
        return forms

    def test_form(self, form):
        marker = f"INJECT-{uuid.uuid4().hex[:8]}"
        data = {}
        for inp in form["inputs"]:
            if inp["type"] in ("hidden", "submit"):
                data[inp["name"]] = inp.get("value", "")
            else:
                data[inp["name"]] = marker

        try:
            if form["method"] == "post":
                r = self.session.post(form["action"] or self.base_url, data=data, timeout=10)
            else:
                r = self.session.get(form["action"] or self.base_url, params=data, timeout=10)
        except Exception as e:
            print("Submit error", form["action"], e)
            return

        if marker in r.text:
            evidence = f"Marker reflected in response for form at {form['action']}"
            self.logger.log(form["action"], "Reflected Input (possible XSS)", "Medium", evidence, detail=str(data))
            print("Possible reflected input:", form["action"])
            return

        db_errors = ["sql syntax", "mysql", "syntax error", "database error", "pdoexception", "pg_query"]
        text_lower = r.text.lower()
        for err in db_errors:
            if err in text_lower:
                evidence = f"Database error string '{err}' present in response"
                self.logger.log(form["action"], "Possible SQL Injection (error-based)", "High", evidence, detail=str(data))
                print("Possible SQLi evidence:", form["action"], err)
                return

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scanner.py https://target.example")
        sys.exit(1)
    target = sys.argv[1]
    logger = Logger()
    s = SimpleScanner(target, logger)
    s.crawl()
    print("Done. Results in vuln_results.db")
