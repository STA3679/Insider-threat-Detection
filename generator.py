import numpy as np
import pandas as pd
import sqlite3
import os
from datetime import datetime, timedelta
import random

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

DB_PATH = r"D:\insider_threat_detection\insider_threat.db"
SEED_CERT_CSV_PATH = r"D:\insider_threat_detection\seed_cert.csv"

def get_employee_baselines():
    """Retrieve employee baseline profiles from SQLite database."""
    if not os.path.exists(DB_PATH):
        # Database hasn't been initialized, return a fallback dict
        return [
            {"employee_id": f"EMP{i:03d}", "baseline_login_start": 9.0, "baseline_login_end": 17.5, 
             "baseline_download_mb": 100.0, "baseline_file_access": 30}
            for i in range(1, 11)
        ]
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT employee_id, baseline_login_start, baseline_login_end, baseline_download_mb, baseline_file_access FROM employees")
    employees = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return employees

def generate_daily_record(emp_baseline, date_str, profile_type="Normal"):
    """
    Generate a daily activity log feature vector for an employee based on their baseline
    and the target profile type (Normal, Suspicious, Threat).
    """
    emp_id = emp_baseline["employee_id"]
    
    # Base values from database/config
    base_login = emp_baseline.get("baseline_login_start", 9.0)
    base_logout = emp_baseline.get("baseline_login_end", 17.5)
    base_download = emp_baseline.get("baseline_download_mb", 100.0)
    base_file_access = emp_baseline.get("baseline_file_access", 30)
    
    # Initialize variables
    login_hour = 9.0
    logout_hour = 17.5
    file_access_count = 0
    usb_usage_count = 0
    email_count = 0
    download_mb = 0.0
    confidential_access_count = 0
    failed_login_count = 0
    unusual_hours = 0
    
    if profile_type == "Normal":
        # Normal behavior modeled with Gaussian and Poisson distributions
        login_hour = np.random.normal(base_login, 0.5)
        # bound to logical ranges
        login_hour = max(6.0, min(12.0, login_hour))
        
        logout_hour = np.random.normal(base_logout, 0.5)
        logout_hour = max(logout_hour, login_hour + 4.0) # at least 4 hours work
        
        file_access_count = int(np.random.poisson(base_file_access))
        usb_usage_count = int(np.random.choice([0, 1, 2], p=[0.85, 0.12, 0.03]))
        email_count = int(np.random.poisson(15))
        download_mb = max(5.0, np.random.normal(base_download, base_download * 0.15))
        
        # Rare events for normal users
        confidential_access_count = int(np.random.choice([0, 1], p=[0.96, 0.04]))
        failed_login_count = int(np.random.choice([0, 1, 2], p=[0.92, 0.07, 0.01]))
        unusual_hours = 0
        label = "Normal"
        
    elif profile_type == "Suspicious":
        # Simulates negligent behavior or minor policy violations
        # e.g., slightly high USB usage or higher download volumes
        login_hour = np.random.normal(base_login, 1.0)
        logout_hour = np.random.normal(base_logout + 1.0, 1.0)
        
        file_access_count = int(np.random.poisson(base_file_access * 1.5))
        usb_usage_count = int(np.random.choice([1, 2, 3], p=[0.5, 0.35, 0.15]))
        email_count = int(np.random.poisson(25))
        download_mb = max(10.0, np.random.normal(base_download * 2.5, base_download * 0.3))
        
        confidential_access_count = int(np.random.choice([1, 2, 3], p=[0.6, 0.3, 0.1]))
        failed_login_count = int(np.random.choice([1, 2, 3, 4], p=[0.4, 0.4, 0.15, 0.05]))
        
        # 30% chance of login outside standard office hours (odd hours)
        if random.random() < 0.3:
            login_hour = float(random.choice([22.0, 23.0, 5.0]))
            unusual_hours = 1
        else:
            unusual_hours = 0
            
        label = "Suspicious"
        
    elif profile_type == "Threat":
        # Simulates a severe insider threat attack vector
        threat_scenario = random.choice(["DataExfiltration", "CredentialAbuse", "DisgruntledSabotage"])
        
        if threat_scenario == "DataExfiltration":
            # High downloads, high USB connects, high confidential accesses
            login_hour = np.random.normal(base_login, 0.5)
            logout_hour = np.random.normal(base_logout, 0.5)
            file_access_count = int(np.random.poisson(base_file_access * 2.5))
            usb_usage_count = int(np.random.randint(4, 9)) # massive USB usage
            email_count = int(np.random.poisson(40))
            download_mb = float(np.random.randint(1500, 5000)) # 1.5GB to 5GB download
            confidential_access_count = int(np.random.randint(10, 35))
            failed_login_count = int(np.random.choice([0, 1], p=[0.8, 0.2]))
            unusual_hours = 0
            
        elif threat_scenario == "CredentialAbuse":
            # Compromised account: logins at 2 AM, high failed login attempts, unusual activity
            login_hour = float(np.random.uniform(0.5, 4.0)) # 12:30 AM to 4 AM
            logout_hour = login_hour + float(np.random.uniform(1.0, 3.0)) # short burst
            file_access_count = int(np.random.randint(80, 200))
            usb_usage_count = int(np.random.choice([0, 1], p=[0.9, 0.1]))
            email_count = 0
            download_mb = float(np.random.randint(100, 500))
            confidential_access_count = int(np.random.randint(5, 20))
            failed_login_count = int(np.random.randint(5, 10)) # high failed attempts before access
            unusual_hours = 1
            
        elif threat_scenario == "DisgruntledSabotage":
            # Policy violation, deleting files (seen as high file access), high email exfiltration
            login_hour = np.random.normal(base_login, 0.5)
            logout_hour = float(random.choice([20.0, 21.0, 22.0])) # working late
            file_access_count = int(np.random.poisson(base_file_access * 3.5)) # high file deletions/modifications
            usb_usage_count = int(np.random.choice([1, 2], p=[0.7, 0.3]))
            email_count = int(np.random.poisson(80)) # sending tons of emails
            download_mb = float(np.random.normal(base_download * 1.5, 20))
            confidential_access_count = int(np.random.randint(8, 15))
            failed_login_count = int(np.random.choice([0, 1, 2], p=[0.8, 0.15, 0.05]))
            unusual_hours = 1 if logout_hour >= 21.0 else 0
            
        label = "Threat"

    return {
        "date": date_str,
        "employee_id": emp_id,
        "login_hour": round(float(login_hour), 2),
        "logout_hour": round(float(logout_hour), 2),
        "file_access_count": int(file_access_count),
        "usb_usage_count": int(usb_usage_count),
        "email_count": int(email_count),
        "download_mb": round(float(download_mb), 2),
        "confidential_access_count": int(confidential_access_count),
        "failed_login_count": int(failed_login_count),
        "unusual_hours": int(unusual_hours),
        "label": label
    }

def generate_dataset(num_days=30, threat_percentage=5):
    """
    Generate a full synthetic dataset for the active employees over a set number of days.
    """
    baselines = get_employee_baselines()
    records = []
    
    start_date = datetime.now() - timedelta(days=num_days)
    
    for day in range(num_days):
        current_date = start_date + timedelta(days=day)
        date_str = current_date.strftime("%Y-%m-%d")
        
        # Exclude weekends (insider activity could happen, but keep standard baseline clean)
        # Saturday = 5, Sunday = 6
        is_weekend = current_date.weekday() >= 5
        
        for emp in baselines:
            # Determine profile type
            # Standard daily work has a very low percentage of threats or suspicious activity
            rand_val = random.random() * 100
            
            # If weekend, lower chance of normal activity, but if there is activity, it's highly suspicious/threat
            if is_weekend:
                if rand_val < 2.0: # 2% chance of working on weekend normally
                    profile = "Normal"
                elif rand_val < 3.5: # suspicious activity
                    profile = "Suspicious"
                elif rand_val < 4.5: # threat weekend access
                    profile = "Threat"
                else:
                    continue # employee did not work this day
            else:
                # Weekdays
                if rand_val < threat_percentage:
                    profile = "Threat"
                elif rand_val < threat_percentage + 10:
                    profile = "Suspicious"
                else:
                    profile = "Normal"
                    
            records.append(generate_daily_record(emp, date_str, profile))
            
    df = pd.DataFrame(records)
    return df

def generate_seed_cert_csv():
    """
    Creates a mock CERT seed dataset (the 'small public dataset') and saves it.
    This simulates real-world scarce dataset features.
    """
    baselines = [
        {"employee_id": f"CERT_EMP{i:03d}", "baseline_login_start": 8.0, "baseline_login_end": 17.0, 
         "baseline_download_mb": 80.0, "baseline_file_access": 25}
        for i in range(1, 6) # 5 static CERT profiles
    ]
    
    records = []
    # Generate 15 days of activity for CERT employees
    start_date = datetime(2025, 1, 1)
    
    for day in range(15):
        current_date = start_date + timedelta(days=day)
        date_str = current_date.strftime("%Y-%m-%d")
        
        for emp in baselines:
            # Generate CERT records with a higher proportion of threats to simulate structured public threat logs
            rand_val = random.random()
            if rand_val < 0.15:
                profile = "Threat"
            elif rand_val < 0.30:
                profile = "Suspicious"
            else:
                profile = "Normal"
            records.append(generate_daily_record(emp, date_str, profile))
            
    df = pd.DataFrame(records)
    # Save to D:\insider_threat_detection\seed_cert.csv
    df.to_csv(SEED_CERT_CSV_PATH, index=False)
    print(f"Mock CERT seed dataset successfully written to: {SEED_CERT_CSV_PATH}")
    return df

def augment_data(df, factor=3):
    """
    Data Augmentation: Extracts suspicious and threat logs from the dataframe
    and generates synthetic variations using Gaussian Noise injection to prevent overfitting
    due to small samples.
    """
    threat_rows = df[df["label"] != "Normal"].copy()
    if len(threat_rows) == 0:
        return df # Nothing to augment
        
    augmented_records = []
    numeric_cols = [
        "login_hour", "logout_hour", "file_access_count", 
        "usb_usage_count", "email_count", "download_mb", 
        "confidential_access_count", "failed_login_count"
    ]
    
    for i in range(factor):
        for idx, row in threat_rows.iterrows():
            new_row = row.copy()
            # Add subtle variations
            for col in numeric_cols:
                val = float(new_row[col])
                if val > 0:
                    # Inject 5% to 15% standard deviation noise
                    noise = np.random.normal(0, max(0.1, val * 0.1))
                    new_val = val + noise
                    # Clean/bound values
                    if "count" in col or col == "failed_login_count":
                        new_row[col] = max(0, int(round(new_val)))
                    else:
                        new_row[col] = round(max(0.0, new_val), 2)
            
            # Ensure logical consistencies
            new_row["login_hour"] = max(0.0, min(23.9, new_row["login_hour"]))
            new_row["logout_hour"] = max(new_row["login_hour"], min(23.9, new_row["logout_hour"]))
            new_row["unusual_hours"] = 1 if (new_row["login_hour"] < 6.0 or new_row["login_hour"] > 22.0 or new_row["logout_hour"] > 21.0) else 0
            
            # Append modified row
            augmented_records.append(new_row)
            
    df_augmented = pd.concat([df, pd.DataFrame(augmented_records)], ignore_index=True)
    return df_augmented

def save_features_to_db(df):
    """Save generated daily features dataframe into the daily_features database table."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # We do a batch insert with INSERT OR REPLACE to allow re-runs
    insert_query = """
    INSERT OR REPLACE INTO daily_features (
        date, employee_id, login_hour, logout_hour, file_access_count, 
        usb_usage_count, email_count, download_mb, confidential_access_count, 
        failed_login_count, unusual_hours, label
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    records_to_insert = []
    for idx, row in df.iterrows():
        # Handle cases where employee ID might not exist in the base table by skipping or using whatever is in DB
        records_to_insert.append((
            row["date"],
            row["employee_id"],
            float(row["login_hour"]),
            float(row["logout_hour"]),
            int(row["file_access_count"]),
            int(row["usb_usage_count"]),
            int(row["email_count"]),
            float(row["download_mb"]),
            int(row["confidential_access_count"]),
            int(row["failed_login_count"]),
            int(row["unusual_hours"]),
            row["label"]
        ))
        
    cursor.executemany(insert_query, records_to_insert)
    conn.commit()
    
    # Let's count current table items
    cursor.execute("SELECT COUNT(*) FROM daily_features")
    total_count = cursor.fetchone()[0]
    conn.close()
    
    print(f"Saved {len(records_to_insert)} records to DB. Total records now in DB: {total_count}")
    return total_count

if __name__ == "__main__":
    # Create the mock seed dataset on initialization
    generate_seed_cert_csv()
    
    # Generate default database synthetic logs
    print("Generating default employee synthetic logs...")
    df_synthetic = generate_dataset(num_days=45, threat_percentage=6)
    save_features_to_db(df_synthetic)
    print("Generator init completed successfully.")
