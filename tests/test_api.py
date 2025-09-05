import unittest
from app import app, init_db

class CVEApiTestCase(unittest.TestCase):
    def setUp(self):
        init_db()
        self.app = app.test_client()

    def test_get_all_cves(self):
        response = self.app.get('/api/cves')
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_filter_by_year(self):
        response = self.app.get('/api/cves?year=2023')
        self.assertEqual(response.status_code, 200)

    def test_filter_by_score(self):
        response = self.app.get('/api/cves?score=7')
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
