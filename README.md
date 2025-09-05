
---

# 📄 **README.md**

```markdown
# 🔐 CVE Management System – NVD Assessment Project

This project is part of the **Securin AI/ML Internship Assessment**.  
It provides a backend + frontend system to fetch, store, and query CVEs (Common Vulnerabilities and Exposures) from the **NVD API**, with features like filtering, validation, server-side sorting, and AI-driven mitigation suggestions.

---

## 🚀 Features
- Periodic **batch sync** with NVD API (incremental updates supported).
- Secure **SQLite3 database** with deduplication & data cleansing.
- REST API built with **Flask**.
- **Validation** for CVE IDs, years, and scores.
- Server-side **sorting by dates**.
- **Mitigation suggestions** (rule-based + AI-ready).
- Frontend with **list view** and **detailed view**.
- Unit-tested with **unittest** + automated GitHub Actions.

---

## 📂 Project Structure
