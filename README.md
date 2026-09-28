
```markdown
# 🛡️ Plaintext SIEM & Real-Time Threat Intelligence Engine

An asynchronous, event-driven Security Information and Event Management (SIEM) pipeline built with Python, FastAPI, DuckDB, and Streamlit. The system simulates real-time security telemetry ingestion, threat intelligence enrichment, stateful rule correlation, and interactive incident forensics.

---

## 📐 Project Architecture

```plaintext
Plaintext_SIEM/
├── config.py            # Global configuration (Host, Port, DB settings)
├── schema.py            # Data models and Event Category definitions
├── generator.py         # Asynchronous telemetry log generator & attack injector
├── threat_intel.py      # Threat intelligence annotation & IP reputation scoring
├── correlation.py       # Stateful rule correlation engine
├── engine.py            # Core analytics engine powered by DuckDB
├── server.py            # FastAPI REST & WebSocket streaming server
└── dashboard.py         # Interactive Streamlit Command & Control dashboard

```

---

## ✨ Features

* **Real-Time Telemetry Streaming:** Simulates system events across Authentication, Network, File System, and Process categories.
* **Threat Intelligence Enrichment:** Automatically flags malicious IP sources and annotates events with reputation scoring.
* **Stateful Rule Engine:** Detects multi-event attack patterns including SSH Brute Force, Port Scanning, and Data Exfiltration.
* **Closed-Loop Attack Injection:** Trigger targeted security attack scenarios directly from the dashboard into the ingestion stream.
* **Incident Forensics & Blast Radius:** Query full historical timelines, targeted accounts, and data footprints for suspicious IP addresses.
* **Threat Velocity Charting:** Time-series aggregation via DuckDB to visualize real-time event spikes during security incidents.

---

## 🚀 Quickstart Guide

### 1. Installation

Clone the repository and install required dependencies:

```bash
git clone [https://github.com/](https://github.com/)<rutush2>/Plaintext_SIEM.git
cd Plaintext_SIEM
pip install fastapi uvicorn streamlit plotly pandas duckdb pydantic

```

### 2. Launch Backend Stream Server

Start the FastAPI ingestion engine:

```bash
python server.py

```

*(Server runs on http://127.0.0.1:8000)*

### 3. Launch Command Center Dashboard

Open a second terminal window and start the Streamlit UI:

```bash
streamlit run dashboard.py

```

*(Dashboard opens at http://localhost:8501)*

---

## 🛠️ Tech Stack

* **Language:** Python 3.12
* **Backend Framework:** FastAPI, Uvicorn
* **Database Engine:** DuckDB
* **Dashboard / UI:** Streamlit, Plotly Express
* **Data Validation:** Pydantic

```

