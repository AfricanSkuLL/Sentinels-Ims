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
            print(f"\n❌ LOCKDOWN TRIGGERED ASYNC BY ANALYST ENGINE!")
            print(f"Server returned 403 Forbidden: {res_data.get('message') or res_data.get('error')}")
            return False
        else:
            print(f"⚠️ Unexpected status: {response.status_code}")
            return True
    except requests.exceptions.RequestException:
        print("❌ CRITICAL: Communication failure.")
        return False

def main():
    print(f"🕵️ [STEALTH DEMO] Starting Low-and-Slow Agent on {DEVICE_NAME}...")

    stealth_events = [
        "Port scan detected on internal subnet range 10.0.0.1/24",
        "Failed SSH authentication attempt for user 'guest'",
        "Unusual outbound TCP connection established to dynamic IP address"
    ]

    print("\n--- Transmitting Bypassing Telemetry ---")
    for i, event in enumerate(stealth_events, 1):
        print(f"\nStealth Pulse {i}/3:")
        if not send_pulse(alert_level=1, details=event):
            return
        time.sleep(2)

    print("\n⏳ Stealth footprints laid. Polling SOC waiting for Analyst daemon detection...")
    while True:
        time.sleep(3)
        if not send_pulse(alert_level=0, details="Standard idle heartbeat pulse."):
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopping stealth simulator.")
