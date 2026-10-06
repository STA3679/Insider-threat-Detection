import sqlite3
import pandas as pd
import numpy as np
import os

DB_PATH = r"D:\insider_threat_detection\insider_threat.db"

class BehaviourProfiler:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        
    def get_connection(self):
        return sqlite3.connect(self.db_path)
        
    def recalculate_all_baselines(self):
        """
        Query the daily_features table for all 'Normal' records of each employee
        and calculate their mean and standard deviation baseline metrics.
        Saves these to the employee records.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Fetch all employees
        cursor.execute("SELECT employee_id FROM employees")
        emp_ids = [row[0] for row in cursor.fetchall()]
        
        updated_count = 0
        
        for emp_id in emp_ids:
            # Get historical normal daily features for this employee
            df_hist = pd.read_sql_query(
                "SELECT login_hour, logout_hour, download_mb, file_access_count FROM daily_features "
                "WHERE employee_id = ? AND label = 'Normal'", 
                conn, 
                params=(emp_id,)
            )
            
            if len(df_hist) < 5:
                # Not enough data, skip recalculating and keep default baseline
                continue
                
            # Calculate averages for normal behavior
            avg_login = float(df_hist["login_hour"].mean())
            avg_logout = float(df_hist["logout_hour"].mean())
            avg_download = float(df_hist["download_mb"].mean())
            avg_file_access = float(df_hist["file_access_count"].mean())
            
            # Update employee table with recalculated baselines
            cursor.execute("""
                UPDATE employees 
                SET baseline_login_start = ?, baseline_login_end = ?, 
                    baseline_download_mb = ?, baseline_file_access = ?
                WHERE employee_id = ?
            """, (round(avg_login, 2), round(avg_logout, 2), round(avg_download, 2), int(round(avg_file_access)), emp_id))
            
            updated_count += 1
            
        conn.commit()
        conn.close()
        print(f"Recalculated baselines for {updated_count} employees.")
        return updated_count

    def get_employee_baseline_profile(self, employee_id):
        """Get baseline details for a specific employee."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT employee_id, name, department, role, 
                   baseline_login_start, baseline_login_end, 
                   baseline_download_mb, baseline_file_access, 
                   threat_score, risk_level
            FROM employees WHERE employee_id = ?
        """, (employee_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def calculate_deviation(self, employee_id, daily_data):
        """
        Compare a single day of employee activity against their baseline.
        Returns:
            deviation_score: float (0 - 100)
            anomalies: list of string descriptions
            explanation: string summarising the anomalies
        """
        baseline = self.get_employee_baseline_profile(employee_id)
        if not baseline:
            return 0.0, [], "Employee baseline profile not found."
            
        anomalies = []
        scores = []
        
        # 1. Login Hour check
        # Allow +/- 1.5 hours deviation as normal, beyond that compute linear penalty
        login_val = daily_data.get("login_hour")
        base_login = baseline["baseline_login_start"]
        login_diff = abs(login_val - base_login)
        if login_val < 6.0 or login_val > 22.0:
            anomalies.append(f"Odd hour login: {login_val:.2f} AM/PM (baseline: {base_login:.2f} AM)")
            scores.append(80.0) # High deviation for midnight logins
        elif login_diff > 2.0:
            anomalies.append(f"Login hour shift: {login_val:.2f} AM/PM (baseline: {base_login:.2f} AM)")
            scores.append(login_diff * 15) # linear score increase
            
        # 2. Logout Hour check
        logout_val = daily_data.get("logout_hour")
        base_logout = baseline["baseline_login_end"]
        if logout_val > 21.0:
            anomalies.append(f"Odd hour logout: {logout_val:.2f} PM (baseline: {base_logout:.2f} PM)")
            scores.append(60.0)
            
        # 3. Download MB check (Use Z-score-like calculation, using 25% of baseline as min std dev)
        download_val = daily_data.get("download_mb", 0.0)
        base_download = baseline["baseline_download_mb"]
        std_download = max(10.0, base_download * 0.15)
        download_z = (download_val - base_download) / std_download
        if download_z > 3.0:
            anomalies.append(f"Abnormal download size: {download_val:.1f} MB (baseline: {base_download:.1f} MB, Z-score: {download_z:.2f})")
            # Cap the score for extremely high downloads
            scores.append(min(100.0, download_z * 15))
            
        # 4. File Access Count check
        file_val = daily_data.get("file_access_count", 0)
        base_file = baseline["baseline_file_access"]
        std_file = max(5.0, base_file * 0.2)
        file_z = (file_val - base_file) / std_file
        if file_z > 3.0:
            anomalies.append(f"High file access rate: {file_val} actions (baseline: {base_file} actions, Z-score: {file_z:.2f})")
            scores.append(min(100.0, file_z * 12))
            
        # 5. USB Usage Count check
        usb_val = daily_data.get("usb_usage_count", 0)
        if usb_val >= 3:
            anomalies.append(f"Multiple USB connections: {usb_val} times (normal is rarely or max 1-2)")
            scores.append(usb_val * 15)
            
        # 6. Confidential File Accesses
        conf_val = daily_data.get("confidential_access_count", 0)
        if conf_val > 0:
            anomalies.append(f"Confidential files accessed: {conf_val} times (sensitive directory access)")
            scores.append(conf_val * 12)
            
        # 7. Failed Logins
        failed_val = daily_data.get("failed_login_count", 0)
        if failed_val >= 3:
            anomalies.append(f"Multiple failed login attempts: {failed_val} times (potential brute force)")
            scores.append(failed_val * 15)
            
        if not scores:
            return 0.0, [], "Normal daily activity parameters."
            
        # Overall deviation score is the weighted average of individual anomaly scores
        # We take the max score as a baseline anchor, and add 20% of the average of the rest
        scores.sort(reverse=True)
        max_score = scores[0]
        if len(scores) > 1:
            other_avg = np.mean(scores[1:])
            overall_score = min(100.0, max_score + (other_avg * 0.2))
        else:
            overall_score = min(100.0, max_score)
            
        overall_score = round(float(overall_score), 2)
        
        # Build explanation
        if anomalies:
            explanation = "Suspicious behavior indicators: " + "; ".join(anomalies)
        else:
            explanation = "Activity aligns with established behavior baseline."
            
        return overall_score, anomalies, explanation

    def update_employee_risk_scores(self):
        """
        Run a pass over all daily features, calculate deviation scores, and update
        the employee's aggregate threat score and risk level.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Get list of employee IDs
        cursor.execute("SELECT employee_id FROM employees")
        emp_ids = [row[0] for row in cursor.fetchall()]
        
        for emp_id in emp_ids:
            # Fetch latest 7 days of daily feature records to assess current risk
            df_recent = pd.read_sql_query(
                "SELECT login_hour, logout_hour, file_access_count, usb_usage_count, "
                "email_count, download_mb, confidential_access_count, failed_login_count, unusual_hours "
                "FROM daily_features WHERE employee_id = ? ORDER BY date DESC LIMIT 7",
                conn,
                params=(emp_id,)
            )
            
            if df_recent.empty:
                continue
                
            # Calculate deviation for each of the recent days and take the max as the current risk score
            recent_scores = []
            for _, row in df_recent.iterrows():
                score, _, _ = self.calculate_deviation(emp_id, row.to_dict())
                recent_scores.append(score)
                
            max_recent_score = max(recent_scores) if recent_scores else 0.0
            
            # Map score to risk level
            if max_recent_score < 30.0:
                risk_level = "Low"
            elif max_recent_score < 70.0:
                risk_level = "Medium"
            else:
                risk_level = "High"
                
            # Update employee table
            cursor.execute(
                "UPDATE employees SET threat_score = ?, risk_level = ? WHERE employee_id = ?",
                (max_recent_score, risk_level, emp_id)
            )
            
        conn.commit()
        conn.close()
        print("Updated risk scores for all employees.")

if __name__ == "__main__":
    profiler = BehaviourProfiler()
    profiler.recalculate_all_baselines()
    profiler.update_employee_risk_scores()
    print("Profiler run completed.")
