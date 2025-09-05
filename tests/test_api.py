import unittest
from app import app, init_db

class CVEApiTestCase(unittest.TestCase):
    def setUp(self):
        # Initialize DB before each test
        init_db()
        self.app = app.test_client()

    # ---------------------- VALID CASES ----------------------
    def test_get_all_cves(self):
        """Test fetching all CVEs"""
        response = self.app.get('/api/cves')
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_filter_by_year(self):
        """Test filtering CVEs by year"""
        response = self.app.get('/api/cves?year=2023')
        self.assertEqual(response.status_code, 200)

    def test_filter_by_score(self):
        """Test filtering CVEs by score"""
        response = self.app.get('/api/cves?score=7')
        self.assertEqual(response.status_code, 200)

    def test_filter_by_valid_cve_id(self):
        """Test filtering by a valid CVE ID"""
        # Replace with a known CVE ID in your DB after sync
        response = self.app.get('/api/cves?id=CVE-1999-0095')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(len(response.get_json()) > 0)

    def test_mitigation_field_present(self):
        """Ensure mitigation advice is included"""
        response = self.app.get('/api/cves')
        self.assertEqual(response.status_code, 200)
        for cve in response.get_json():
            self.assertIn("mitigation", cve)

    def test_html_list_route(self):
        """Test /cves/list renders HTML"""
        response = self.app.get('/cves/list')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<table", response.data)

def test_html_details_route(self):
        """Test /cves/<cve_id> renders HTML"""
        response = self.app.get('/cves/CVE-1999-0095')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CVE-1999-0095", response.data)

    # ---------------------- INVALID CASES ----------------------
    def test_invalid_year(self):
        """Test invalid year input"""
        response = self.app.get('/api/cves?year=abcd')
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid year", response.get_json().get("error", ""))

    def test_invalid_score_non_numeric(self):
        """Test invalid non-numeric score"""
        response = self.app.get('/api/cves?score=abc')
        self.assertEqual(response.status_code, 400)
        self.assertIn("Score must be a number", response.get_json().get("error", ""))

    def test_invalid_score_out_of_range(self):
        """Test invalid score outside range 0–10"""
        response = self.app.get('/api/cves?score=15')
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid score", response.get_json().get("error", ""))

    def test_invalid_cve_id(self):
        """Test invalid CVE ID format"""
        response = self.app.get('/api/cves?id=BADID')
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid CVE ID format", response.get_json().get("error", ""))


if __name__ == "__main__":
    unittest.main()
