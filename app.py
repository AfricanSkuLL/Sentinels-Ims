import os
from flask import Flask, request, jsonify, render_template
from cs50 import SQL

app = Flask(__name__)

# Ensure absolute file path resolution for Vercel/Serverless execution environments
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sentinel.db")

# Initialize SQLite database instance
db = SQL(f"sqlite:///{DB_PATH}")


def init_db():
    """Ensures required tables and administrative state exist on launch."""
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            strike_count INTEGER DEFAULT 0,
            is_locked BOOLEAN DEFAULT FALSE,
            last_strike_reason TEXT
        )
    """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            device_name TEXT,
            event_details TEXT,
            alert_level INTEGER DEFAULT 0
        )
    """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_value TEXT NOT NULL,
            threat_severity INTEGER DEFAULT 1
        )
    """
    )
    # Seed default administrative node if absent
    admin = db.execute("SELECT id FROM users WHERE username = ?", "admin")
    if not admin:
        db.execute(
            "INSERT INTO users (username, strike_count, is_locked) VALUES (?, ?, ?)",
            "admin",
            0,
            False,
        )


# Run database check on startup
try:
    init_db()
except Exception as e:
    print(f"Database initialization warning: {e}")


@app.route("/", methods=["GET"])
def index():
    """Serves the main security control panel template."""
    return render_template("index.html")


@app.route("/ingest", methods=["POST"])
def ingest():
    """
    The Central SOC Controller: Receives pulses, checks for strikes,
    and executes the 'Kill Switch' if 3 strikes are confirmed.
    """
    # 1. LOCKDOWN GATEKEEPER: Check if account exists and if it is already locked
    user_status = db.execute(
        "SELECT strike_count, is_locked FROM users WHERE username = ?", "admin"
    )

    if not user_status:
        return jsonify({"error": "UNAUTHORIZED_NODE"}), 401

    if user_status[0]["is_locked"]:
        return (
            jsonify(
                {
                    "error": "SENTINEL LOCKDOWN ACTIVE",
                    "code": "FIREWALL_BLOCK",
                    "status": "TERMINATED",
                    "message": "Sentinel Lockdown Active",
                }
            ),
            403,
        )

    # 2. DATA ACQUISITION: Parse JSON from the Inquisitor (Sensor)
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid Data Packet"}), 400

    device = data.get("device", "Unknown Device")
    event_details = data.get("event_details", "Standard Pulse")
    alert_level = data.get("alert_level", 0)

    # 3. LOGGING: Record the raw pulse with the correct alert level
    db.execute(
        "INSERT INTO logs (device_name, event_details, alert_level) VALUES (?, ?, ?)",
        device,
        event_details,
        alert_level,
    )

    # 4. THREAT MATCHING: Check against the Threat Database
    threat = db.execute(
        "SELECT threat_severity FROM threat_signatures WHERE ? LIKE '%' || pattern_value || '%'",
        event_details,
    )

    # Track live metric adjustments within this lifecycle frame
    current_strike_count = user_status[0]["strike_count"]

    if threat:
        severity = threat[0]["threat_severity"]

        # 5. EXECUTE STRIKE: Increment the count in the database
        db.execute(
            "UPDATE users SET strike_count = strike_count + ? WHERE username = ?",
            severity,
            "admin",
        )

        # 6. FINAL VALIDATION: Re-check if this strike triggered the 3-strike limit
        updated_user = db.execute(
            "SELECT strike_count FROM users WHERE username = ?", "admin"
        )
        current_strike_count = updated_user[0]["strike_count"]

        if current_strike_count >= 3:
            db.execute(
                "UPDATE users SET is_locked = TRUE, last_strike_reason = ? WHERE username = ?",
                event_details,
                "admin",
            )
            return (
                jsonify(
                    {
                        "error": "SENTINEL LOCKDOWN ACTIVE",
                        "code": "FIREWALL_BLOCK",
                        "status": "LOCKDOWN_TRIGGERED",
                        "reason": event_details,
                        "message": f"Lockdown triggered by: {event_details}",
                    }
                ),
                403,
            )

    return (
        jsonify(
            {
                "status": "SUCCESS",
                "message": "Pulse Ingested",
                "strike_count": current_strike_count,
            }
        ),
        200,
    )


@app.route("/status", methods=["GET"])
def status():
    """
    Dashboard Synchronizer: Fetches administrative state and recent logs
    to populate the UI feed.
    """
    user_data = db.execute(
        "SELECT strike_count, is_locked FROM users WHERE username = ?", "admin"
    )
    if not user_data:
        return jsonify({"error": "Admin node offline"}), 404

    log_data = db.execute(
        "SELECT datetime(timestamp, 'localtime') AS timestamp, device_name, event_details, alert_level FROM logs ORDER BY timestamp DESC LIMIT 50"
    )

    return jsonify({"user": user_data[0], "logs": log_data}), 200


@app.route("/reset", methods=["POST"])
def reset():
    """
    Administrative Override: Clears strike counts, lifts lockdowns,
    and flushes historical telemetry data.
    """
    db.execute(
        "UPDATE users SET strike_count = 0, is_locked = FALSE, last_strike_reason = NULL WHERE username = 'admin'"
    )
    db.execute("DELETE FROM logs")
    return (
        jsonify({"status": "SUCCESS", "message": "Security baseline restored"}),
        200,
    )


if __name__ == "__main__":
    app.run()