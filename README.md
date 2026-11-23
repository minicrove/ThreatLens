# 🛡️ ThreatLens — Security Log Analyzer

A Python + Streamlit educational security monitoring dashboard that analyzes authentication logs and flags repeated failed logins within a sliding time window.

## Features
- CSV upload with timestamp, IP, username and login-status validation
- Configurable failed-login threshold and time window
- IP-based suspicious-login alerts with illustrative risk scores
- Interactive charts, searchable events, and downloadable alerts
- Automated tests using pytest

## Setup (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -v
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open http://localhost:8501 . On macOS/Linux use `python3 -m venv .venv` and `.venv/bin/python` in place of `.\.venv\Scripts\python.exe`.

## Input format
CSV with `timestamp,ip_address,username,status` columns. Status must be `success` or `failed`. Example data are in `data/sample_logs.csv`. Timestamps without a timezone are interpreted as UTC. Invalid rows are discarded and exact duplicates removed.

## Detection logic
For each IP, find at least N failed login events within a sliding window of M minutes. Alerts for the same ongoing burst are suppressed to reduce noise. This prototype does not automatically block IPs.

## Limitations & privacy
This is a rule-based educational prototype, **not** a production SIEM. Its risk scores are illustrative, not calibrated. Review alerts manually; false positives are possible. Only upload logs you are authorized to use. Never commit real credentials, private user logs, or sensitive data to public GitHub repositories. For real-world integrations, implement proper access controls, retention, privacy safeguards and secure deployment.

## Roadmap
- Additional detection rules and unit tests
- Windows/Linux log format adapters
- SQLite and real-time ingestion
- Evaluated anomaly-detection model

## License
No license is granted until a license file is added. Add a license if you wish to permit reuse.
=======
# ThreatLens
ThreatLens is an interactive cybersecurity dashboard designed to analyze authentication logs, detect suspicious login activities, and visualize potential security threats.

