from flask import Flask, jsonify, request, render_template
import requests
import sqlite3
import threading
import time
import re
from datetime import datetime

app = Flask(__name__)
DB_NAME = "cves.db"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# DB Setup
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY,
            published TEXT,
            lastModified TEXT,
            description TEXT,
            cvss_score REAL
        )
    """)
    conn.commit()
    conn.close()

# Sync Data
def fetch_and_store_cves():
    start_index = 0
    results_per_page = 100
    while True:
        url = f"{NVD_API}?startIndex={start_index}&resultsPerPage={results_per_page}"
        resp = requests.get(url)
        if resp.status_code != 200:
            break
        data = resp.json()
        cves = data.get("vulnerabilities", [])
        if not cves:
            break
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        for item in cves:
            cve_id = item["cve"]["id"]
            if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
                continue
            published = item["cve"].get("published")
            modified = item["cve"].get("lastModified")
            published = published.split("T")[0] if published else None
            modified = modified.split("T")[0] if modified else None
            description = item["cve"]["descriptions"][0]["value"] if item["cve"].get("descriptions") else ""
            score = None
            metrics = item["cve"].get("metrics", {})
            if "cvssMetricV3" in metrics:
                score = metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            try:
                score = float(score) if score is not None else None
                if score is not None and (score < 0 or score > 10):
                    score = None
            except (ValueError, TypeError):
                score = None
            cursor.execute("""
                INSERT OR REPLACE INTO cves (id, published, lastModified, description, cvss_score)
                VALUES (?, ?, ?, ?, ?)
            """, (cve_id, published, modified, description, score))
        conn.commit()
        conn.close()
        start_index += results_per_page

# Run sync in background
def periodic_sync(interval=86400):
    while True:
        fetch_and_store_cves()
        time.sleep(interval)

# Mitigation Suggestion
def suggest_mitigation(description, score):
    desc = (description or "").lower()
    # Rule-based patterns
    if "sql injection" in desc:
        return "Use parameterized queries, ORM frameworks, and strict input validation."
    elif "buffer overflow" in desc:
        return "Apply vendor patches, enable DEP/ASLR, and use memory-safe languages/libraries."
    elif "xss" in desc or "cross-site scripting" in desc:
        return "Sanitize user inputs, encode outputs, and apply CSP headers."
    elif "privilege escalation" in desc:
        return "Update OS/software, enforce least privilege, and monitor logs."
    elif "dos" in desc or "denial of service" in desc:
        return "Rate limit requests, use WAF, and monitor traffic anomalies."
    elif "rce" in desc or "remote code execution" in desc:
        return "Patch immediately, restrict remote access, and apply network segmentation."
    elif score and score >= 7:
        return "Apply patches immediately, restrict exposure, and monitor advisories."
    else:
        return "Review vendor advisories and apply patches when available."

# API Endpoints
@app.route("/api/cves", methods=["GET"])
def get_cves():
    year = request.args.get("year")
    cve_id = request.args.get("id")
    score = request.args.get("score")
    query = "SELECT * FROM cves WHERE 1=1"
    params = []
    if cve_id:
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            return jsonify({"error": "Invalid CVE ID format"}), 400
        query += " AND id = ?"
        params.append(cve_id)
    if year:
        if not year.isdigit() or not (1999 <= int(year) <= datetime.now().year):
            return jsonify({"error": "Invalid year"}), 400
        query += " AND published LIKE ?"
        params.append(f"{year}%")
    if score:
        try:
            score = float(score)
            if score < 0 or score > 10:
                return jsonify({"error": "Invalid score"}), 400
        except ValueError:
            return jsonify({"error": "Score must be a number"}), 400
        query += " AND cvss_score >= ?"
        params.append(score)
    sort = request.args.get("sort")
    valid_sorts = {
        "published_asc": "published ASC",
        "published_desc": "published DESC",
        "modified_asc": "lastModified ASC",
        "modified_desc": "lastModified DESC"
    }
    if sort in valid_sorts:
        query += f" ORDER BY {valid_sorts[sort]}"
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    results = [{
        "id": r[0],
        "published": r[1],
        "lastModified": r[2],
        "description": r[3],
        "cvss_score": r[4],
        "mitigation": suggest_mitigation(r[3], r[4])
    } for r in rows]
    return jsonify(results)

@app.route("/cves/list")
def cves_list():
    return render_template("list.html")

@app.route("/cves/<cve_id>")
def cve_details(cve_id):
    return render_template("details.html", cve_id=cve_id)

# Main
if __name__ == "__main__":
    init_db()
    threading.Thread(target=periodic_sync, daemon=True).start()
    app.run(debug=True, use_reloader=False) # use_reloader=False
