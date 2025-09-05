# **README.md**

```markdown
NVD-CVE_API

The CVE API is used to easily retrieve information on a single CVE or a collection of CVE from the NVD. 
It provides a backend + frontend system to fetch, store, and query CVEs (Common Vulnerabilities and Exposures) from the **NVD API**, with features like filtering, validation, server-side sorting, and AI-driven mitigation suggestions.

---

Features
- Periodic batch sync with NVD API (incremental updates supported).
- Secure SQLite3 database with deduplication & data cleansing.
- REST API built with Flask.
- Validation for CVE IDs, years, and scores.
- Server-side sorting by dates.
- Mitigation suggestions (rule-based + AI-ready).
- Frontend with list view and detailed view.
- Unit-tested with unittest + automated GitHub Actions.

---

## Project Structure
NVD-CVE_API/
│── app.py # Flask backend
│── cves.db # SQLite DB (auto-created)
│── requirements.txt # Dependencies
│── templates/
│ ├── list.html # CVE list page
│ ├── details.html # CVE details page
│── static/
│ ├── style.css # Styling
│ └── script.js # JS logic
│── tests/
│ └── test_api.py # Unit tests
│── docs/
│ └── API_Documentation.md
│── README.md

---

Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/GnanambalM/NVD-CVE_API.git
cd NVD-CVE_API

### 2. Install Dependencies
pip install -r requirements.txt

### 3. Run the Application
python app.py

Visit:

API: http://127.0.0.1:5000/api/cves

List View: http://127.0.0.1:5000/cves/list

Running Tests
python -m unittest discover -s tests -p "test_*.py"

GitHub Actions workflow (.github/workflows/test.yml) automatically runs these tests on every push.
