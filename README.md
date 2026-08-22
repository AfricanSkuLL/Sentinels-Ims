markdown_content = """# Sentinel: Automated SOC & Incident Isolation System

#### Video Demo: [https://youtu.be/SgZ2PiwxjNg](https://youtu.be/SgZ2PiwxjNg)

---

## 1. System Overview

**Sentinels-Ims** is a lightweight, three-tier Security Operations Center (SOC) and automated Incident Management System (IMS). Built as a full-stack, distributed security simulation, the platform mirrors real-world enterprise cyber defense models. In modern security environments, manual analysis of threats is too slow to stop automated exploits; Sentinel addresses this by demonstrating how immediate **signature matching** can be combined with **behavioral heuristics** to dynamically quarantine compromised machines.

The architecture is divided into three key decoupled components working in synchronization:
1. **The Ingestion & Control Hub (Web Dashboard):** A Flask web application that acts as the primary API endpoint and administrative interface. It renders a real-world dark-mode terminal monitoring panel that polls security states asynchronously.
2. **The Asynchronous Heuristics Engine (The Analyst):** An out-of-band daemon running concurrently to process behavioral sequences over time. It identifies stealthy "low-and-slow" attacks that bypass static signature matchers.
3. **The Distributed Endpoint Sensors (The Agents):** Endpoint daemons running on target systems that package and transmit telemetry data using encrypted-style REST payloads.

---

## 2. File Breakdown

### `app.py` (Central SOC Controller & API)
This is the heart of the system. It initializes the Flask web server, establishes the SQL database gateway, and exposes three primary API endpoints:
* `/` (GET): Serves the frontend web UI dashboard.
* `/status` (GET): A REST endpoint utilized by the front-end javascript poller to dynamically stream user lockdown status and the latest 50 security telemetry logs without requiring a browser refresh.
* `/ingest` (POST): The central intake port. It acts as a primary gatekeeper, rejecting traffic from already locked-down nodes (403 Forbidden), recording inbound telemetry, and comparing event details against defined SQL database threat signatures. If an instant signature is hit, it scales user strikes and executes an atomic lockout.
* `/reset` (POST): An administrative override endpoint to restore the security baseline and flush logs.

### `analyst.py` (Asynchronous Background Heuristics Engine)
The analyst daemon serves as an advanced threat hunter. Running in a continuous background loop, it performs out-of-band analysis of database events. It checks logs generated over the last 5 minutes to correlate sequential anomalies that look benign individually but constitute an attack vector (such as port scans followed by failed logins). Once it identifies a threshold of 3 or more warnings from a single host, it flags a "Lateral Movement" heuristic alarm, writes a sequence alert log, increments the target strike count, and enforces account lockouts independently of `app.py`.

### `agent.py` & `agent_stealth.py` (Endpoint Sensors)
These files act as endpoint telemetry simulators:
* `agent.py` simulates normal network behavior for a baseline window (Cycles 1 to 5), allowing administrators to witness "STABLE" states on camera. It then transitions to a series of high-severity burst signature attacks (such as reading `/etc/shadow`), validating the fast-path signature blocking mechanism.
* `agent_stealth.py` simulates a stealth operator. It carefully spaces out low-severity warnings (Alert Level 1) that bypass static signature filters, remaining undetected by the Flask ingest controller. This file tests and validates the asynchronous detection cycle of `analyst.py`.

### `templates/index.html` (Frontend Terminal Dashboard)
The visualization tier of Sentinel. To avoid the generic appearance of standard administrative portals, it is designed with a high-fidelity, responsive cyber-security operations skin. Using vanilla JavaScript, it polls `/status` every 2 seconds to update dynamic indicators (Strike levels, Lockdown text, connection state) and builds an live-scrolling alert ledger where warnings flash dynamically based on received alert levels.

### `init_db.py` (Database Schema Provisioner)
A database initialization script that establishes the database structure, provisions our primary administrative target, and populates the static threat signature definitions (e.g., matching SQL patterns like `etc/shadow` or `rm -rf`).

---

## 3. Critical Design Choices & Engineering Challenges

### The Choice of SQLite
For an MVP enterprise platform, SQLite was chosen over heavy alternatives like PostgreSQL or MySQL. SQLite is incredibly lightweight, serverless, and requires zero configuration, making it highly portable and ideal for a CS50 submission. Furthermore, because Python’s `cs50.SQL` library handles connection pooling natively, it allowed us to demonstrate ACID-compliant database writes from multiple concurrent processes (the Flask server inserting and reading logs, and the Analyst daemon reading and updating user states) without complex database migrations.

### The Timezone Logic Trap
One of the most complex engineering challenges faced during development was navigating the timezone mismatch between SQLite's server-side engines and client-side visualization.

* **The Problem:** By default, SQLite stores timestamps using UTC (`CURRENT_TIMESTAMP`). When the Flask server wrote logs, they were recorded in UTC. However, when the Analyst engine scanned for logs using `datetime('now', '-5 minutes', 'localtime')`, it queried based on the host machine's physical timezone clock. If the user lived in a timezone UTC+2, the analyst evaluated the "last 5 minutes" using localized time, concluding that UTC logs were generated 2 hours ago. Consequently, no heuristic threat sequences were ever matched.
* **The Solution:** We cleanly separated storage representation from presentation. Raw storage calculations inside `analyst.py` were locked strictly to UTC using raw SQLite `datetime('now', '-5 minutes')` offsets. To keep the frontend human-readable, the database-to-UI query inside `app.py` was adjusted using the SQLite `localtime` transform modifier:
  `SELECT datetime(timestamp, 'localtime') AS timestamp...`
  This unified background analysis globally while translating log feeds beautifully on our monitor dashboard to reflect the administrator’s exact wall-clock time.

---

## 4. Installation & Deployment Guide

To run Sentinels-Ims, execute the following commands in three split-terminal sessions:

### Step 1: Initialize the Database
Before booting the engines, construct the database file and initial tables:
SUCCESS: README.md successfully created!

```bash
python init_db.py
Step 2: Start the Central SOC Hub (Terminal 1)
This boots the Flask daemon and dashboard UI.

python app.py
Open http://127.0.0.1:5000/ in your browser to view the active console.

Step 3: Start the Heuristics Engine (Terminal 2)
This starts the asynchronous pattern scanning loop.

python analyst.py
Step 4: Run an Endpoint Simulator (Terminal 3)
Choose either the rapid signature check:

python agent.py
Or test the advanced heuristic sequence hunter:

python agent_stealth.py
"""
