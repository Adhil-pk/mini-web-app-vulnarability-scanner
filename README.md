# WebApp Vulnerability Scanner (mini)

A small, learning-focused web application vulnerability scanner with a Flask UI.
**Important:** This project is for learning and authorized testing only.

## Features
- Crawls same-domain pages
- Discovers HTML forms and inputs
- Performs safe marker-based injection tests (reflection check, simple DB error heuristics)
- Stores findings in a local SQLite DB (`vuln_results.db`)
- Small Flask UI to start scans and view results

## Quick start
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
