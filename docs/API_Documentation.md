# CVE Management API – Documentation

This API provides access to CVE (Common Vulnerabilities and Exposures) data synchronized from the [NVD API](https://nvd.nist.gov/developers).  
It supports filtering, validation, sorting, and mitigation suggestions.

---

## Base URL
`http://127.0.0.1:5000/api`

---

## Endpoints

### 1. Get All CVEs
**Request**


GET /api/cves


**Response**
```json
[
  {
    "id": "CVE-2023-12345",
    "published": "2023-05-01",
    "lastModified": "2023-05-10",
    "description": "SQL Injection vulnerability in ...",
    "cvss_score": 9.8,
    "mitigation": "Use parameterized queries, ORM frameworks, and strict input validation."
  }
]

2. Filter by Year

Request

GET /api/cves?year=2023


Response
Returns all CVEs published in 2023.

3. Filter by CVE ID

Request

GET /api/cves?id=CVE-2023-12345


Response
Returns details for the specified CVE ID.

4. Filter by Score

Request

GET /api/cves?score=7


Response
Returns CVEs with CVSS score ≥ 7.0.

5. Sorting (Server-side)

Request

GET /api/cves?sort=published_desc


Valid Values

published_asc

published_desc

modified_asc

modified_desc

Response
Returns CVEs sorted based on the requested order.

⚠️ Error Handling

Invalid inputs return a 400 Bad Request with descriptive error messages.

Examples

Invalid year

GET /api/cves?year=abcd


Response

{"error": "Invalid year. Must be between 1999 and current year."}


Invalid score (non-numeric)

GET /api/cves?score=abc


Response

{"error": "Score must be a number"}


Invalid CVE ID format

GET /api/cves?id=BADID


Response

{"error": "Invalid CVE ID format. Expected CVE-YYYY-NNNN"}

🛡️ Data Quality & Sync

Data is fetched in batches from NVD API.

Deduplication is ensured via PRIMARY KEY (CVE ID).

Dates are normalized to YYYY-MM-DD.

Scores validated between 0–10.

CVEs refreshed periodically (default: every 24 hours).

🔮 AI-Powered Mitigation

Each CVE includes a mitigation field with recommended remediation strategies.

Rule-based logic matches common vulnerability patterns (SQLi, XSS, RCE, etc).

Extensible to use AI/ML models for intelligent suggestions.

Example

{
  "id": "CVE-2023-56789",
  "description": "Buffer overflow in ...",
  "cvss_score": 8.5,
  "mitigation": "Apply vendor patches, enable DEP/ASLR, and use memory-safe libraries."
}
