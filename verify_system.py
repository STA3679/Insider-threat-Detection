import os
import unittest
import sqlite3
import pandas as pd
import json

from database import DB_PATH, get_db
from generator import generate_daily_record
from profiler import BehaviourProfiler
from ml_engine import MLEngine, FEATURE_COLS
from app import app

class TestSentinelSystem(unittest.TestCase):
    def setUp(self):
        self.db_path = DB_PATH
        self.app_client = app.test_client()
        self.app_client.testing = True

    def test_database_connection(self):
        """Test if the SQLite database exists and has table rows."""
        self.assertTrue(os.path.exists(self.db_path), "Database file does not exist.")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Test employees count
        cursor.execute("SELECT COUNT(*) FROM employees")
        count = cursor.fetchone()[0]
        self.assertGreater(count, 0, "No seeded employees found.")
        
        # Test features table exists
        cursor.execute("SELECT COUNT(*) FROM daily_features")
        features_cnt = cursor.fetchone()[0]
        self.assertGreaterEqual(features_cnt, 0, "daily_features table query failed.")
        
        conn.close()
        print("[SUCCESS] Database schema and records verified.")

    def test_profiler_deviations(self):
        """Test if the behaviour profiler correctly flags abnormal logs."""
        profiler = BehaviourProfiler()
        
        # Base employee profile (Alice)
        baseline = profiler.get_employee_baseline_profile("EMP001")
        self.assertIsNotNone(baseline)
        
        # Test 1: Normal record matching baseline
        normal_data = {
            "login_hour": baseline["baseline_login_start"],
            "logout_hour": baseline["baseline_login_end"],
            "file_access_count": baseline["baseline_file_access"],
            "usb_usage_count": 0,
            "email_count": 10,
            "download_mb": baseline["baseline_download_mb"],
            "confidential_access_count": 0,
            "failed_login_count": 0,
            "unusual_hours": 0
        }
        
        score_normal, anomalies_normal, _ = profiler.calculate_deviation("EMP001", normal_data)
        self.assertLess(score_normal, 20.0, f"Normal daily record flagged with high deviation score: {score_normal}")
        self.assertEqual(len(anomalies_normal), 0, "Normal log should have no anomalies.")

        # Test 2: Threat record (large download, USB plug-ins, off-office hours)
        threat_data = {
            "login_hour": 3.0, # 3 AM (Unusual)
            "logout_hour": 5.0,
            "file_access_count": baseline["baseline_file_access"] * 5, # 5x accesses
            "usb_usage_count": 5, # 5 USB connections
            "email_count": 2,
            "download_mb": baseline["baseline_download_mb"] * 10, # 10x download size
            "confidential_access_count": 12, # high confidential files access
            "failed_login_count": 5, # failed logins
            "unusual_hours": 1
        }
        
        score_threat, anomalies_threat, explanation = profiler.calculate_deviation("EMP001", threat_data)
        self.assertGreater(score_threat, 70.0, f"Extreme threat record generated low deviation score: {score_threat}")
        self.assertGreater(len(anomalies_threat), 3, "Threat record should trigger multiple anomalies.")
        self.assertIn("download", explanation.lower())
        self.assertIn("usb", explanation.lower())
        print("[SUCCESS] Behaviour profiling baseline deviations working correctly.")

    def test_ml_engine(self):
        """Test ML training outputs, active model loading, and predictions."""
        engine = MLEngine()
        
        # Retrieve saved metrics
        metrics = engine.get_metrics()
        self.assertGreater(len(metrics), 0, "No metrics saved in model_metrics table.")
        
        # Test individual inference (Random Forest classifier)
        test_feature = {
            "login_hour": 9.0, "logout_hour": 17.5, "file_access_count": 30, "usb_usage_count": 0,
            "email_count": 12, "download_mb": 100.0, "confidential_access_count": 0, "failed_login_count": 0, "unusual_hours": 0
        }
        
        pred_res = engine.predict_threat("Random_Forest", test_feature)
        self.assertEqual(pred_res["prediction"], "Normal", f"Clear normal vector predicted as: {pred_res['prediction']}")
        self.assertGreater(pred_res["confidence"], 50.0)
        
        print("[SUCCESS] ML Engine inference & Explainable AI output verified.")

    def test_flask_routing(self):
        """Test Flask application pages and streaming APIs response codes."""
        # Test Home/Dashboard
        resp = self.app_client.get("/")
        self.assertEqual(resp.status_code, 200, "Dashboard index route failed.")
        self.assertIn(b"Security Admin Dashboard", resp.data)
        
        # Test Live Stream Simulation API
        resp_sim = self.app_client.get("/api/sim_event")
        self.assertEqual(resp_sim.status_code, 200, "Simulation API endpoint failed.")
        
        data = json.loads(resp_sim.data.decode('utf-8'))
        self.assertIn("employee_id", data)
        self.assertIn("prediction", data)
        self.assertIn("explanation", data)
        
        print("[SUCCESS] Flask routing, server logic, and simulator REST APIs verified.")

if __name__ == "__main__":
    unittest.main()
