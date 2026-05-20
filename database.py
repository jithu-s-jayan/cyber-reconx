import sqlite3
import os
import time
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'recon.db')

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Self-healing migration check: Check if scan_history exists and has user_id
    try:
        cursor.execute("PRAGMA table_info(scan_history)")
        columns = [col[1] for col in cursor.fetchall()]
        if columns and 'user_id' not in columns:
            # Legacy table detected without user_id! Drop legacy tables to recreate cleanly
            print("[DB] Legacy database schema detected (missing user_id). Running schema recreation...")
            cursor.execute("DROP TABLE IF EXISTS scan_history")
            cursor.execute("DROP TABLE IF EXISTS activity_logs")
            cursor.execute("DROP TABLE IF EXISTS users")
            conn.commit()
    except Exception as e:
        print(f"[DB] Error checking legacy schema: {e}")

    # 1. Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            name TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT 'local', -- 'local' or 'google'
            avatar TEXT
        )
    ''')
    
    # 2. Scan History Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            timestamp REAL NOT NULL,
            threat_level TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            summary TEXT NOT NULL,
            details TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # 3. Activity Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

# --- USER AUTHENTICATION ACTIONS ---

def create_user(email, password, name, provider='local', avatar=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    password_hash = generate_password_hash(password) if password else None
    
    try:
        cursor.execute('''
            INSERT INTO users (email, password_hash, name, provider, avatar)
            VALUES (?, ?, ?, ?, ?)
        ''', (email.strip().lower(), password_hash, name.strip(), provider, avatar))
        conn.commit()
        user_id = cursor.lastrowid
        
        # Add initial activity log for user boot
        conn.close()
        add_activity_log(user_id, "SYSTEM_INIT", f"Operator registration complete for {name} ({email}).")
        return {"id": user_id, "email": email, "name": name, "provider": provider, "avatar": avatar}
    except sqlite3.IntegrityError:
        conn.close()
        return None  # Email already exists

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE email = ? AND provider = "local"', (email.strip().lower(),))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        return dict(user)
    return None

def find_or_create_google_user(email, name, google_id, avatar=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    email_clean = email.strip().lower()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email_clean,))
    user = cursor.fetchone()
    
    if user:
        # If user exists, return
        conn.close()
        return dict(user)
    else:
        # Create Google authenticated user
        cursor.execute('''
            INSERT INTO users (email, password_hash, name, provider, avatar)
            VALUES (?, ?, ?, ?, ?)
        ''', (email_clean, None, name.strip(), 'google', avatar))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        add_activity_log(user_id, "SYSTEM_INIT", f"Google Authentication operator initialized: {name}.")
        return {"id": user_id, "email": email_clean, "name": name, "provider": "google", "avatar": avatar}

def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, name, provider, avatar FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

# --- TELEMETRY & OSINT RECORD ACTIONS (ISOLATED BY USER_ID) ---

def add_scan(user_id, scan_type, target, threat_level, threat_score, summary, details):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = time.time()
    
    cursor.execute('''
        INSERT INTO scan_history (user_id, scan_type, target, timestamp, threat_level, threat_score, summary, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, scan_type, target, timestamp, threat_level, threat_score, summary, details))
    
    conn.commit()
    conn.close()
    
    # Also log this as an isolated user activity log
    add_activity_log(user_id, "SCAN_COMPLETED", f"Completed {scan_type} on target: {target}. Severity: {threat_level}.")

def get_scan_history(user_id, limit=10):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scan_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?', (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_scan_by_id(user_id, scan_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scan_history WHERE id = ? AND user_id = ?', (scan_id, user_id))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def add_activity_log(user_id, event_type, message):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = time.time()
    cursor.execute('''
        INSERT INTO activity_logs (user_id, timestamp, event_type, message)
        VALUES (?, ?, ?, ?)
    ''', (user_id, timestamp, event_type, message))
    conn.commit()
    conn.close()

def get_activity_logs(user_id, limit=20):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?', (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM scan_history WHERE user_id = ?', (user_id,))
    total_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND threat_level = "High"', (user_id,))
    high_threats = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND threat_level = "Medium"', (user_id,))
    medium_threats = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND (threat_level = "Low" OR threat_level = "Info")', (user_id,))
    low_threats = cursor.fetchone()[0]
    
    cursor.execute('SELECT AVG(threat_score) FROM scan_history WHERE user_id = ?', (user_id,))
    avg_score_raw = cursor.fetchone()[0]
    avg_score = round(avg_score_raw) if avg_score_raw else 0
    
    conn.close()
    
    return {
        "total_scans": total_scans,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,
        "avg_score": avg_score
    }
