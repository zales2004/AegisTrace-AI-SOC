# AegisTrace – AI-Powered SOC Investigation Platform

**Detect the threat. Trace the evidence. Verify the response.**

## Overview

AegisTrace is a Python-based SOC investigation prototype that brings security alert monitoring, evidence-based event correlation, threat intelligence and AI-assisted investigation into one platform. It is designed to help analysts understand related security events and review potential attack activity.

## Key Features

- **Wazuh Monitoring:** Retrieve alerts from the Wazuh Indexer and maintain searchable alert history.
- **Linux Threat Detection:** Collect SSH authentication events and identify repeated failures or successful logins following failures.
- **Evidence-Based Correlation:** Group related Wazuh events using timestamps, host identity, account, IP address, process and other available evidence.
- **AI-Assisted Investigation:** Generate structured investigation narratives with a locally hosted Ollama model. AI output is checked against available evidence and security references.
- **Threat Intelligence:** Enrich public IP addresses and SHA-256 file hashes using the VirusTotal API, with queued lookups and result caching.
- **File Monitoring:** Monitor configured directories, calculate file hashes and maintain file activity history.
- **Quarantine:** Support analyst-initiated and threshold-based automatic quarantine, with hash verification and an audit trail.
- **Security References:** Use MITRE ATT&CK technique data and MITRE D3FEND catalogue/mapping data to provide defensive context.

## Architecture

```text
 Wazuh Indexer ───── Linux Authentication Logs
       │                         │
       ▼                         ▼
              AegisTrace
       ┌──────────────────────────────┐
       │       FastAPI Backend       │
       │                              │
       │  Alert Ingestion & Storage  │
       │  Detection & Correlation    │
       │  Evidence Assessment        │
       │  Threat Intelligence        │
       │  File Monitoring/Quarantine │
       └──────────────┬───────────────┘
                      │
             Investigation Engine
                ┌─────┴─────┐
                ▼           ▼
             Ollama     MITRE Data
                │
                ▼
       Investigation Findings
                      │
                      ▼
             SOC Web Dashboard
```

## How It Works

1. **Collect:** Retrieve Wazuh alerts and collect Linux authentication events.
2. **Detect:** Identify suspicious authentication patterns and review incoming alerts.
3. **Correlate:** Link events only when available evidence supports a relationship; retain the supporting reasons and source alert IDs.
4. **Investigate:** Produce an AI-assisted narrative for a candidate event chain, using local Ollama inference and reference validation.
5. **Enrich:** Query VirusTotal for eligible public IP addresses and file hashes; consult ATT&CK and D3FEND reference data.
6. **Respond:** Review file activity and use the audited quarantine workflow when its conditions are met.

## Technology Stack

| Area | Technology |
|---|---|
| Language / Backend | Python, FastAPI |
| API Server | Uvicorn |
| Storage | SQLite |
| Security Monitoring | Wazuh Indexer |
| Threat Intelligence | VirusTotal API |
| Local AI | Ollama |
| Security References | MITRE ATT&CK, MITRE D3FEND |
| Version Control | Git, GitHub |

## Setup

1. Clone the repository and enter the project directory:
   ```bash
   git clone https://github.com/zales2004/AegisTrace-AI-SOC.git
   cd AegisTrace-AI-SOC
   ```
2. Create and activate the project environment:
   ```bash
   python3 -m venv .aegis
   source .aegis/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env` and configure the Wazuh Indexer, VirusTotal, Ollama, database and file-monitoring settings.
5. Start the API:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```
6. Open `http://127.0.0.1:8000` in a browser.

**Reference data requirement:** The MITRE reference loader expects these files in `data/reference/`: `enterprise-attack.json`, `d3fend.csv` and `d3fend-full-mappings.csv`. The two D3FEND CSV files are included in the repository. The ATT&CK Enterprise STIX file must be obtained separately from the official [MITRE ATT&CK STIX data repository](https://github.com/mitre-attack/attack-stix-data) and placed in that directory.

## Project Structure

```text
AegisTrace-AI-SOC/
├── collectors/       # Linux authentication event collection
├── database/         # SQLite storage and Wazuh alert history
├── detection/        # SSH authentication detection
├── integrations/     # VirusTotal, file monitoring and quarantine
├── investigation/    # Correlation, evidence and AI investigation
├── data/reference/   # MITRE reference datasets
├── main.py           # FastAPI application
├── requirements.txt  # Python dependencies
└── .env.example      # Configuration template
```

## Project Status

AegisTrace is an actively developed project prototype. Integrations require local configuration and testing; it is not intended to replace a production SOC or an analyst's final judgement. Correlation scores indicate support for event relationships, not the probability that an attack occurred. AI-generated findings should be reviewed against the original evidence.

## Author

**Alen Sales K S** · [GitHub](https://github.com/zales2004)
