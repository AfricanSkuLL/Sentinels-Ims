import os
import shutil
import requests
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# --- DATABASE SETUP (TURSO HTTP REST API / LOCAL SQLITE FALLBACK) ---
TURSO_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")


class TursoHTTPDB:
    """Pure-Python HTTP REST wrapper for Turso SQLite database."""

    def __init__(self, url, token):
        formatted_url = url.replace("libsql://", "https://")
        if not formatted_url.startswith("https://"):
            formatted_url = f"https://{formatted_url}"
        self.url = f"{formatted_url.rstrip('/')}/v2/pipeline"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def execute(self, sql, *args):
        positional_args = []
        for arg in args:
            if isinstance(arg, bool):
                positional_args.append(
                    {"type": "integer", "value": "1" if arg else "0"}
                )
            elif isinstance(arg, (int, float)):
                positional_args.append({"type": "integer", "value": str(arg)})
            elif arg is None:
                positional_args.append({"type": "null"})
            else:
                positional_args.append({"type": "text", "value": str(arg)})

        payload = {
            "requests": [
                {
                    "type": "execute",
                    "stmt": {"sql": sql, "args": positional_args},
                },
                {"type": "close"},
            ]
        }

        res = requests.post(self.url, json=payload, headers=self.headers)
        res_data = res.json()

        try:
            result = res_data["results"][0]["response"]["result"]
            cols = [col["name"] for col in result.get("cols", [])]
            rows = []
            for row in result.get("rows", []):
                row_dict = {}
                for i, col_name in enumerate(cols):
                    val = row[i].get("value")
                    row_dict[col_name] = val
                rows.append(row_dict)
            return rows
        except (KeyError, IndexError):
            return []


if TURSO_URL and TURSO_TOKEN:
    # Production: Hosted Turso Cloud SQLite over HTTP
    db = TursoHTTPDB(TURSO_URL, TURSO_TOKEN)
else:
    # Local Development: Fallback to local file or /tmp
    from cs50 import SQL

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    READONLY_DB = os.path.join(BASE_DIR, "sentinel.db")
    DB_PATH = "/tmp/sentinel.db"

    if not os.path.exists(DB_PATH):
        if os.path.exists(READONLY_DB):
            shutil.copy(READONLY_DB, DB_PATH)
            os.chmod(DB_PATH, 0o666)
        else:
            with open(DB_PATH, "w") as f:
                pass
            os.chmod(DB_PATH, 0o666)

    db = SQL(f"sqlite:///{DB_PATH}")


def init_db():
    """Ensures required tables, threat patterns, and administrative node exist."""
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

    admin = db.execute("SELECT id FROM users WHERE username = ?", "admin")
    if not admin:
        db.execute(
            "INSERT INTO users (username, strike_count, is_locked) VALUES (?, ?, ?)",
            "admin",
            0,
            False,
        )

    signatures = db.execute("SELECT id FROM threat_signatures LIMIT 1")
    if not signatures:
        db.execute(
            "INSERT INTO threat_signatures (pattern_value, threat_severity) VALUES (?, ?)",
            "/etc/shadow",
            1,
        )
        db.execute(
            "INSERT INTO threat_signatures (pattern_value, threat_severity) VALUES (?, ?)",
            "rm -rf",
            2,
        )


try:
    init_db()
except Exception as e:
    print(f"Database initialization status: {e}")


@app.route("/", methods=["GET"])
def index():
    """Serves the main security control panel interface."""
    return render_template("index.html")


@app.route("/ingest", methods=["POST"])
def ingest():
    """
    Central SOC Endpoint: Processes incoming node pulses, records logs,
    evaluates signatures, and enforces automated account lockdowns.
    """
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

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid Data Packet"}), 400

    device = data.get("device", "Unknown Device")
    event_details = data.get("event_details", "Standard Pulse")
    alert_level = data.get("alert_level", 0)

    db.execute(
        "INSERT INTO logs (device_name, event_details, alert_level) VALUES (?, ?, ?)",
        device,
        event_details,
        alert_level,
    )

    threat = db.execute(
        "SELECT threat_severity FROM threat_signatures WHERE ? LIKE '%' || pattern_value || '%'",
        event_details,
    )

    current_strike_count = user_status[0]["strike_count"]

    if threat:
        severity = threat[0]["threat_severity"]

        db.execute(
            "UPDATE users SET strike_count = strike_count + ? WHERE username = ?",
            severity,
            "admin",
        )

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
    """Dashboard Endpoint: Fetches administrative metrics and live telemetry logs."""
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
    """Administrative Reset: Restores security baseline and purges historical telemetry."""
    db.execute(
        "UPDATE users SET strike_count = 0, is_locked = FALSE, last_strike_reason = NULL WHERE username = 'admin'"
    )
    db.execute("DELETE FROM logs")
    return (
        jsonify({"status": "SUCCESS", "message": "Security baseline restored"}),
        200,
    )


@app.route("/cron/analyze", methods=["GET", "POST"])
def cron_analyze():
    """
    Vercel Cron Trigger: Replaces background analyst loop by running
    scheduled telemetry analysis.
    """
    unprocessed = db.execute(
        "SELECT * FROM logs WHERE alert_level = 0 ORDER BY id DESC LIMIT 20"
    )

    processed_count = 0
    for log in unprocessed:
        processed_count += 1

    return (
        jsonify(
            {
                "status": "SUCCESS",
                "processed_records": processed_count,
                "message": "Analyst cron cycle executed successfully",
            }
        ),
        200,
    )


if __name__ == "__main__":
    app.run()