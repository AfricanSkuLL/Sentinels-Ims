-- 1. The Users Table: Stores identity and the 'Kill Switch' status
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,

    -- Security Columns for the Agentic SOC
    strike_count INTEGER DEFAULT 0,
    is_locked BOOLEAN DEFAULT FALSE,
    last_strike_reason TEXT
);

-- 2. Records pulses and threats
-- By including 'device_name', here we remove the need for a separate nodes table
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_name TEXT,     -- e.g., 'SENTINEL_NODE_01'
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT,          -- Heartbeat status (e.g., 'ACTIVE')
    event_details TEXT,   -- Description of activity (e.g., 'Accessing /etc/shadow')
    alert_level INTEGER   -- 0 for normal, 1+ for suspicious activity
);

-- 3. Threat Signature Table: The "Match" Database
-- This is used to check if the incoming pulse matches a known threat pattern
CREATE TABLE threat_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type TEXT,    -- e.g., 'FILE_PATH'
    pattern_value TEXT,   -- e.g., '/etc/shadow'
    threat_severity INTEGER -- How many strikes this event adds to the user
);
