# NVD-CVE_API – Documentation

This API provides access to CVE (Common Vulnerabilities and Exposures) data synchronized from the [NVD API](https://nvd.nist.gov/developers).  
The system supports filtering, validation, sorting, and mitigation suggestions.

---

## Base URL

http://127.0.0.1:5000/api


---

## 📂 Endpoints

### 1. Get All CVEs
**Request:**

GET /api/cves

**Response:**

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

**### 2. Filter by year**
**Request:**

GET /api/cves?year=2023

**Response:** Returns CVEs published in 2023.

**### 3. Filter by CVE ID**
**Request:**

GET /api/cves?id=CVE-2023-12345

**Response:** Returns details of the given CVE ID.

**### 4. Filter by Score**
**Request:**

GET /api/cves?score=7

Response: Returns CVEs with CVSS score ≥ 7.0.

**### 5. Sorting (Server-side)**
**Request:**

GET /api/cves?sort=published_desc
Mitigation strategies automatically suggested.
