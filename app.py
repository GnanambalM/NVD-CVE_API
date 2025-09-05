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
            cvss_score REAL,
            status TEXT,
            severity TEXT,
            vector TEXT,
            access_vector TEXT,
            access_complexity TEXT,
            authentication TEXT,
            confidentiality TEXT,
            integrity TEXT,
            availability TEXT,
            exploitability_score REAL,
            impact_score REAL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cpe (
            cve_id TEXT,
            criteria TEXT,
            matchCriteriaId TEXT,
            vulnerable TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(id)
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
            description = item["cve"].get("descriptions", [{}])[0].get("value", "")
            status = item["cve"].get("vulnStatus", "Unknown")
            severity = vector = access_vector = access_complexity = authentication = ""
            confidentiality = integrity = availability = ""
            exploitability_score = impact_score = None
            score = None
            metrics = item["cve"].get("metrics", {})
            if "cvssMetricV3" in metrics:
                score = metrics["cvssMetricV3"][0]["cvssData"].get("baseScore")
            elif "cvssMetricV2" in metrics:
                v2 = metrics["cvssMetricV2"][0]["cvssData"]
                score = v2.get("baseScore")
                severity = v2.get("severity")
                vector = v2.get("vectorString")
                access_vector = v2.get("accessVector")
                access_complexity = v2.get("accessComplexity")
                authentication = v2.get("authentication")
                confidentiality = v2.get("confidentialityImpact")
                integrity = v2.get("integrityImpact")
                availability = v2.get("availabilityImpact")
                exploitability_score = v2.get("exploitabilityScore")
                impact_score = v2.get("impactScore")
            try:
                score = float(score) if score is not None else None
                if score is not None and (score < 0 or score > 10):
                    score = None
            except (ValueError, TypeError):
                score = None
            cursor.execute("""
                INSERT OR REPLACE INTO cves (
                    id, published, lastModified, description, cvss_score, status,
                    severity, vector, access_vector, access_complexity, authentication,
                    confidentiality, integrity, availability, exploitability_score, impact_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id, published, modified, description, score, status,
                severity, vector, access_vector, access_complexity, authentication,
                confidentiality, integrity, availability, exploitability_score, impact_score
            ))
            cursor.execute("DELETE FROM cpe WHERE cve_id = ?", (cve_id,))
            configs = item["cve"].get("configurations", [])
            for config in configs:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria")
                        match_id = match.get("matchCriteriaId")
                        vulnerable = "Yes" if match.get("vulnerable") else "No"
                        cursor.execute("""
                            INSERT INTO cpe (cve_id, criteria, matchCriteriaId, vulnerable)
                            VALUES (?, ?, ?, ?)
                        """, (cve_id, criteria, match_id, vulnerable))
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
    results = []
    for r in rows:
        cursor.execute("SELECT criteria, matchCriteriaId, vulnerable FROM cpe WHERE cve_id = ?", (r[0],))
        cpe_rows = cursor.fetchall()
        cpes = [{"criteria": c[0], "matchCriteriaId": c[1], "vulnerable": c[2]} for c in cpe_rows]
        results.append({
            "id": r[0],
            "published": r[1],
            "lastModified": r[2],
            "description": r[3],
            "cvss_score": r[4],
            "status": r[5],
            "identifier": "cve@mitre.org",
            "mitigation": suggest_mitigation(r[3], r[4]),
            "exploitabilityScore": r[14],
            "impactScore": r[15],
            "cvss": {
                "severity": r[6],
                "vectorString": r[7],
                "accessVector": r[8],
                "accessComplexity": r[9],
                "authentication": r[10],
                "confidentialityImpact": r[11],
                "integrityImpact": r[12],
                "availabilityImpact": r[13],
                "score": r[4]
            },
            "cpes": cpes
        })
    conn.close()
    return jsonify(results)

@app.route("/cves/list")
def cves_list():
    return render_template("list.html")

@app.route("/cves/<cve_id>")
def cve_details(cve_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cves WHERE id = ?", (cve_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return "CVE not found", 404
    cursor.execute("SELECT criteria, matchCriteriaId, vulnerable FROM cpe WHERE cve_id = ?", (cve_id,))
    cpe_rows = cursor.fetchall()
    cpes = [{"criteria": r[0], "matchCriteriaId": r[1], "vulnerable": r[2]} for r in cpe_rows]
    cve_data = {
        "id": row[0],
        "published": row[1],
        "lastModified": row[2],
        "description": row[3],
        "cvss_score": row[4],
        "status": row[5],
        "severity": row[6],
        "vector": row[7],
        "access_vector": row[8],
        "access_complexity": row[9],
        "authentication": row[10],
        "confidentiality": row[11],
        "integrity": row[12],
        "availability": row[13],
        "exploitabilityScore": row[14],
        "impactScore": row[15],
        "mitigation": suggest_mitigation(row[3], row[4]),
        "cvss": {
            "severity": row[6],
            "vectorString": row[7],
            "accessVector": row[8],
            "accessComplexity": row[9],
            "authentication": row[10],
            "confidentialityImpact": row[11],
            "integrityImpact": row[12],
            "availabilityImpact": row[13],
            "score": row[4]
        },
        "cpes": cpes
    }
    conn.close()
    return render_template("details.html", cve=cve_data)

# Main
if __name__ == "__main__":
    init_db()
    threading.Thread(target=periodic_sync, daemon=True).start()
    app.run(debug=True, use_reloader=False)
