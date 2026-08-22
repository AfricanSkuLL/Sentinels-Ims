import time
from cs50 import SQL

# Initialize database connection
db = SQL("sqlite:///sentinel.db")


def run_analysis_cycle():
    """
    The Analyst logic: Periodically reviews the 'logs' table to find
    patterns that a single ingestion pulse might miss.
    """
    print("--- Analyst Cycle Starting: Evaluating Sequences ---")

    # 1. Fetch unanalyzed logs within the active 5-minute UTC window
    recent_logs = db.execute(
        "SELECT * FROM logs WHERE timestamp > datetime('now', '-5 minutes')"
    )

    # 2. SEQUENCE CHECK: Look for 'Lateral Movement' patterns
    threat_map = {}
    for log in recent_logs:
        device = log["device_name"]
        if device not in threat_map:
            threat_map[device] = 0

        # Count suspicious activity indicators
        if log["alert_level"] and log["alert_level"] > 0:
            threat_map[device] += 1

    # 3. ACTION: Apply strikes and validate active system lockout thresholds
    for device, alert_count in threat_map.items():
        if alert_count >= 3:
            print(
                f"🚨 ALARM: Sequential threat detected on {device} ({alert_count} hits). Issuing Strike."
            )

            # Target the 'admin' user for the MVP lockout logic
            db.execute(
                "UPDATE users SET strike_count = strike_count + 1 WHERE username = 'admin'"
            )

            # HEURISTIC LOCKDOWN ADJUSTMENT: Check if this strike breaches the defensive threshold
            user_data = db.execute(
                "SELECT strike_count FROM users WHERE username = 'admin'"
            )
            if user_data and user_data[0]["strike_count"] >= 3:
                print("🔒 LOCKDOWN CRITERIA MET: Locking down user account 'admin'.")
                db.execute(
                    "UPDATE users SET is_locked = TRUE, last_strike_reason = ? WHERE username = 'admin'",
                    f"Heuristic sequence block: {alert_count} suspicious events detected by analyst",
                )

            # Record the Analyst's finding explicitly into the security panel telemetry stream
            db.execute(
                "INSERT INTO logs (device_name, event_details, alert_level) VALUES (?, ?, ?)",
                device,
                f"Analyst engine detected sequence of {alert_count} alerts over 5 mins.",
                2,
            )


def main():
    while True:
        run_analysis_cycle()
        # 30-second sleep to allow telemetry pulses to accumulate
        time.sleep(30)


if __name__ == "__main__":
    main()
