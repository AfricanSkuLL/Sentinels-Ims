import os
import sqlite3
from cs50 import SQL

DB_FILE = "sentinel.db"

# 1. Force remove the old DB if it exists
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

# 2. Use native sqlite3 to safely register and flush the file onto the disk
conn = sqlite3.connect(DB_FILE)
conn.close()

# 3. Now hand it off to CS50 safely
db = SQL(f"sqlite:///{DB_FILE}")

print("⏳ Creating schemas...")

# 4. Create Tables
db.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    strike_count INTEGER DEFAULT 0,
    is_locked BOOLEAN DEFAULT FALSE,
    last_strike_reason TEXT
);
""")

db.execute("""
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_name TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT,
    event_details TEXT,
    alert_level INTEGER
);
""")

db.execute("""
CREATE TABLE threat_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type TEXT,
    pattern_value TEXT,
    threat_severity INTEGER
);
""")

# 5. Seed Baseline Security Profiles
db.execute("INSERT INTO users (username, hash, strike_count, is_locked) VALUES ('admin', 'mock_hash', 0, FALSE);")
db.execute("INSERT INTO threat_signatures (pattern_type, pattern_value, threat_severity) VALUES ('FILE_PATH', '/etc/shadow', 1);")
db.execute("INSERT INTO threat_signatures (pattern_type, pattern_value, threat_severity) VALUES ('COMMAND', 'rm -rf', 2);")

print("✅ Database successfully linked and baseline profiles seeded.")
