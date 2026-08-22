import time
import requests
from datetime import datetime

DEVICE_NAME = "SENTINEL_NODE_01"
SOC_URL = "http://127.0.0.1:5000/ingest"

def send_pulse(alert_level, details):
    """Formats and transmits security data to the central SOC endpoint."""
    pulse_data = {
        "device": DEVICE_NAME,
        "alert_level": alert_level,
        "event_details": details
    }
    try:
        response = requests.post(SOC_URL, json=pulse_data, timeout=3)
        res_data = response.json() if response.content else {}

        if response.status_code == 200:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 Pulse Accepted -> {details} (Strike Count: {res_data.get('strike_count', 0)})")
            return True
        elif response.status_code == 403:
            print(f"\n❌ LOCKDOWN TRIGGERED INSTANTLY BY APP.PY!")
            print(f"Server returned 403 Forbidden: {res_data.get('message') or res_data.get('error')}")
            return False
        else:
            print(f"⚠️ Unexpected status: {response.status_code}")
            return True
    except requests.exceptions.RequestException:
        print("❌ CRITICAL: Communication failure. Is Flask running?")
        return False

def main():
    print(f"🚀 [DIRECT ATTACK DEMO] Starting Agent on {DEVICE_NAME}...")

    # Phase 1: Clean Baseline (Fast-paced for demo video)
    print("\n--- Establishing Baseline Telemetry ---")
    for i in range(1, 3):
        if not send_pulse(alert_level=0, details="System telemetry normal. Performance baseline optimal."):
            return
        time.sleep(3)

    # Phase 2: Direct High-Severity Signature Match
    print("\n⚠️ [ATTACK] Transmitting Known Threat Signatures...")
    attacks = [
        "Unauthorized user reading /etc/shadow",
        "Suspicious runtime execution: rm -rf /var/log",
        "Attempting persistent access sequence"
    ]

    for attack in attacks:
        time.sleep(2)
        if not send_pulse(alert_level=2, details=attack):
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopping Agent daemon gracefully.")
