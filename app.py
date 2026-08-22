from flask import Flask, request, jsonify, render_template
from cs50 import SQL

app = Flask(__name__)
db = SQL("sqlite:///sentinel.db")

@app.route("/", methods=["GET"])
def index():
    """Serves the main security control panel template"""
    return render_template("index.html")

@app.route("/ingest", methods=["POST"])
def ingest():
    """
    The Central SOC Controller: Receives pulses, checks for strikes,
    and executes the 'Kill Switch' if 3 strikes are confirmed.
    """
    # 1. LOCKDOWN GATEKEEPER: Check if account exists and if it is already locked
    user_status = db.execute("SELECT strike_count, is_locked FROM users WHERE username = ?", "admin")

    if not user_status:
        return jsonify({"error": "UNAUTHORIZED_NODE"}), 401

    if user_status[0]["is_locked"]:
        return jsonify({
            "error": "SENTINEL LOCKDOWN ACTIVE",
            "code": "FIREWALL_BLOCK",
            "status": "TERMINATED",
            "message": "Sentinel Lockdown Active"
        }), 403

    # 2. DATA ACQUISITION: Parse JSON from the Inquisitor (Sensor)
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid Data Packet"}), 400

    device = data.get("device")
    event_details = data.get("event_details", "Standard Pulse")
    alert_level = data.get("alert_level", 0)  # Dynamically captured from agent payload

    # 3. LOGGING: Record the raw pulse with the correct alert level
    db.execute(
        "INSERT INTO logs (device_name, event_details, alert_level) VALUES (?, ?, ?)",
        device, event_details, alert_level
    )

    # 4. THREAT MATCHING: Check against the Threat Database
    threat = db.execute(
        "SELECT threat_severity FROM threat_signatures WHERE ? LIKE '%' || pattern_value || '%'",
        event_details
    )

    # Track live metric adjustments within this lifecycle frame
    current_strike_count = user_status[0]["strike_count"]

    if threat:
        severity = threat[0]["threat_severity"]

        # 5. EXECUTE STRIKE: Increment the count in the database
        db.execute(
            "UPDATE users SET strike_count = strike_count + ? WHERE username = ?",
            severity, "admin"
        )

        # 6. FINAL VALIDATION: Re-check if this strike triggered the 3-strike limit
        updated_user = db.execute("SELECT strike_count FROM users WHERE username = ?", "admin")
        current_strike_count = updated_user[0]["strike_count"]

        if current_strike_count >= 3:
            db.execute("UPDATE users SET is_locked = TRUE, last_strike_reason = ? WHERE username = ?",
                       event_details, "admin")
            return jsonify({
                "error": "SENTINEL LOCKDOWN ACTIVE",
                "code": "FIREWALL_BLOCK",
                "status": "LOCKDOWN_TRIGGERED",
                "reason": event_details,
                "message": f"Lockdown triggered by: {event_details}"
            }), 403

    # Return calculated current_strike_count rather than the stale user_status snapshot
    return jsonify({
        "status": "SUCCESS",
        "message": "Pulse Ingested",
        "strike_count": current_strike_count
    }), 200

@app.route("/status", methods=["GET"])
def status():
    """
    Dashboard Synchronizer: Fetches the administrative state and recent logs
    to populate the UI feed.
    """
    user_data = db.execute("SELECT strike_count, is_locked FROM users WHERE username = ?", "admin")
    if not user_data:
        return jsonify({"error": "Admin node offline"}), 404

    # Corrected timestamp conversion query and aligned indentation blocks
    log_data = db.execute("SELECT datetime(timestamp, 'localtime') AS timestamp, device_name, event_details, alert_level FROM logs ORDER BY timestamp DESC LIMIT 50")

    return jsonify({
        "user": user_data[0],
        "logs": log_data
    }), 200

@app.route("/reset", methods=["POST"])
def reset():
    """
    Administrative Override: Clears the strike counts, lifts lockdowns,
    and flushes historical telemetry data.
    """
    db.execute("UPDATE users SET strike_count = 0, is_locked = FALSE, last_strike_reason = NULL WHERE username = 'admin'")
    db.execute("DELETE FROM logs")
    return jsonify({"status": "SUCCESS", "message": "Security baseline restored"}), 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
