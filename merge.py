import os
import time
import requests
from datetime import datetime

# ========================================== #
# CONFIGURATION                              #
# ========================================== #
DEVICE_NAME = "SENTINEL_NODE_01"
SOC_URL = "https://sentinels-ims.vercel.app/ingest"

# ========================================== #
# TELEMETRY TRANSMITTER                      #
# ========================================== #
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
            strike_count = res_data.get("strike_count", 0)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 Pulse Accepted -> {details} (Strike Count: {strike_count})")
            return True
        elif response.status_code == 403:
            print(f"\n❌ [403 FORBIDDEN] LOCKDOWN ACTIVE!")
            error_msg = res_data.get("message") or res_data.get("error") or "Access Denied by SOC Firewall."
            print(f"    Reason: {error_msg}")
            return False
        elif response.status_code == 401:
            print(f"❌ [401 UNAUTHORIZED]: {res_data.get('error', 'Node non-authenticated')}")
            return False
        else:
            print(f"⚠️ [HTTP {response.status_code}]: Unexpected server status.")
            return True

    except requests.exceptions.RequestException as e:
        print(f"❌ CRITICAL: Could not reach SOC at {SOC_URL}. Is Flask running?")
        return False


# ========================================== #
# UNIFIED STRESS & AUDIT SEQUENCE            #
# ========================================== #
def main():
    print("=" * 60)
    print(f"🚀 SENTINEL INTEGRATED AUDIT AGENT: {DEVICE_NAME}")
    print(f"📡 TARGET SOC ENDPOINT: {SOC_URL}")
    print("=" * 60)

    # -----------------------------------------------------------------
    # PHASE 1: Baseline Telemetry (Clean Traffic)
    # -----------------------------------------------------------------
    print("\n[PHASE 1] Establishing Baseline Telemetry...")
    for i in range(1, 3):
        print(f"  Pulse {i}/2: Sending clean heartbeat...")
        if not send_pulse(alert_level=0, details="System telemetry normal. Performance baseline optimal."):
            print("Aborting: System already locked down prior to test.")
            return
        time.sleep(2)

    # -----------------------------------------------------------------
    # PHASE 2: Stealth Probes (Tests Asynchronous analyst.py Detection)
    # -----------------------------------------------------------------
    print("\n[PHASE 2] Executing Stealth Probe Sequence...")
    stealth_events = [
        "Port scan detected on internal subnet range 10.0.0.1/24",
        "Failed SSH authentication attempt for user 'guest'",
        "Unusual outbound TCP connection established to dynamic IP address"
    ]

    for i, event in enumerate(stealth_events, 1):
        print(f"  Stealth Probe {i}/{len(stealth_events)}...")
        if not send_pulse(alert_level=1, details=event):
            print("  🔒 Lockdown triggered early during stealth probes!")
            return
        time.sleep(2)

    # -----------------------------------------------------------------
    # PHASE 3: High-Severity Burst (Tests Real-Time app.py Signature Match)
    # -----------------------------------------------------------------
    print("\n[PHASE 3] Initiating High-Severity Signature Burst...")
    direct_bursts = [
        (2, "Unauthorized user reading /etc/shadow"),
        (2, "Suspicious runtime execution: rm -rf /var/log"),
        (2, "Attempting persistent access sequence")
    ]

    for level, details in direct_bursts:
        print(f"  High-Severity Burst: Transmitting alert_level={level}...")
        if not send_pulse(alert_level=level, details=details):
            print("  🔒 Lockdown triggered during signature burst!")
            return
        time.sleep(2)

    # -----------------------------------------------------------------
    # PHASE 4: Post-Attack Verification Loop
    # -----------------------------------------------------------------
    print("\n[PHASE 4] Attack sequence complete. Monitoring SOC response status...")
    attempts = 0
    while attempts < 10:
        attempts += 1
        time.sleep(3)
        print(f"  Verification check {attempts}/10...")
        if not send_pulse(alert_level=0, details="Verification heartbeat pulse."):
            print("\n✅ AUDIT COMPLETE: Sentinel SOC successfully enforced system lockdown!")
            return

    print("\n⚠️ AUDIT WARNING: Sent all attack vectors but the account remains unlocked. Check analyst.py daemon execution.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nStopping agent audit sequence.")
