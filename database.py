import sqlite3
import os

DB_PATH = r"D:\insider_threat_detection\insider_threat.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Ensure directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Employees Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS employees (
        employee_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        department TEXT NOT NULL,
        role TEXT NOT NULL,
        baseline_login_start REAL DEFAULT 8.0,
        baseline_login_end REAL DEFAULT 18.0,
        baseline_download_mb REAL DEFAULT 150.0,
        baseline_file_access INTEGER DEFAULT 50,
        threat_score REAL DEFAULT 0.0,
        risk_level TEXT DEFAULT 'Low' -- 'Low', 'Medium', 'High'
    )
    """)
    
    # 2. Raw Event Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS raw_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        employee_id TEXT NOT NULL,
        activity_type TEXT NOT NULL, -- LOGIN, LOGOUT, FILE_ACCESS, USB_CONNECT, EMAIL_SENT, DOWNLOAD, CONFIDENTIAL_ACCESS, FAILED_LOGIN
        detail_val REAL DEFAULT 0.0, -- Download size in MB, or failed login count, etc.
        description TEXT,
        FOREIGN KEY(employee_id) REFERENCES employees(employee_id)
    )
    """)
    
    # 3. Daily Behavior Features Table (for training and evaluation)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS daily_features (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        employee_id TEXT NOT NULL,
        login_hour REAL,
        logout_hour REAL,
        file_access_count INTEGER DEFAULT 0,
        usb_usage_count INTEGER DEFAULT 0,
        email_count INTEGER DEFAULT 0,
        download_mb REAL DEFAULT 0.0,
        confidential_access_count INTEGER DEFAULT 0,
        failed_login_count INTEGER DEFAULT 0,
        unusual_hours INTEGER DEFAULT 0, -- 1 if unusual, 0 otherwise
        label TEXT DEFAULT 'Normal', -- 'Normal', 'Suspicious', 'Threat'
        prediction TEXT, -- Prediction output by model
        prediction_model TEXT, -- Which model made the prediction
        FOREIGN KEY(employee_id) REFERENCES employees(employee_id),
        UNIQUE(date, employee_id)
    )
    """)
    
    # 4. Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        employee_id TEXT NOT NULL,
        risk_score REAL NOT NULL,
        alert_type TEXT NOT NULL, -- e.g., 'Data Exfiltration', 'Credential Abuse', 'Odd Working Hours'
        description TEXT NOT NULL,
        status TEXT DEFAULT 'Active', -- 'Active', 'Resolved'
        FOREIGN KEY(employee_id) REFERENCES employees(employee_id)
    )
    """)
    
    # 5. Model Metrics Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS model_metrics (
        model_name TEXT PRIMARY KEY,
        accuracy REAL,
        precision REAL,
        recall REAL,
        f1_score REAL,
        trained_on_synthetic_count INTEGER,
        trained_on_seed_count INTEGER,
        last_updated TEXT
    )
    """)
    
    conn.commit()
    
    # Seed default employees if table is empty
    cursor.execute("SELECT COUNT(*) FROM employees")
    if cursor.fetchone()[0] == 0:
        default_employees = [
            ("EMP001", "Alice Vance", "R&D", "Senior Researcher", 8.5, 17.5, 120.0, 45),
            ("EMP002", "Bob Smith", "Sales", "Account Manager", 9.0, 18.0, 50.0, 20),
            ("EMP003", "Charlie Brown", "Finance", "Accountant", 8.0, 17.0, 30.0, 15),
            ("EMP004", "Diana Prince", "IT Admin", "System Administrator", 7.5, 18.5, 350.0, 120),
            ("EMP005", "Evan Wright", "HR", "Recruiter", 9.0, 17.5, 40.0, 25),
            ("EMP006", "Fiona Gallagher", "Marketing", "Content Creator", 10.0, 18.5, 150.0, 30),
            ("EMP007", "George Miller", "R&D", "Developer", 9.0, 18.0, 200.0, 80),
            ("EMP008", "Hannah Abbott", "Operations", "Logistics Coordinator", 8.0, 16.5, 60.0, 35),
            ("EMP009", "Ian Malcolm", "R&D", "Data Analyst", 8.5, 17.5, 250.0, 70),
            ("EMP010", "Julia Roberts", "Executive", "Director", 9.0, 17.0, 80.0, 40)
        ]
        cursor.executemany("""
        INSERT INTO employees (employee_id, name, department, role, baseline_login_start, baseline_login_end, baseline_download_mb, baseline_file_access)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, default_employees)
        conn.commit()
        print("Default employees seeded successfully.")
        
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at:", DB_PATH)
