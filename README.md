# Dragos OT Security for Splunk App

## Overview

Dragos OT Security is a purpose-built cybersecurity platform designed to protect **industrial control systems (ICS)** and **operational technology (OT)** environments.

Dragos provides deep visibility into OT networks by monitoring industrial protocols, asset behavior, and adversary activity across critical infrastructure environments such as manufacturing, energy, utilities, transportation, and industrial facilities.

Dragos continuously analyzes OT assets, communications, and threats without disrupting industrial processes. The platform is engineered to operate safely in sensitive environments where availability, safety, and reliability are paramount.

The **Dragos OT Security for Splunk App** is a single Splunk application that ingests telemetry, alerts, detections, asset inventory, network activity, and threat intelligence from a Dragos platform using the **Dragos REST API**.

Data is ingested into a user-specified Splunk index and assigned explicit sourcetypes per dataset. All data is stored in **raw JSON format** to preserve fidelity, structure, and future extensibility.

The Splunk App provides dashboards, reports, and search logic for analyzing Dragos OT security data directly within Splunk.

This includes OT alerts and detections, asset inventory, network protocol activity, threat intelligence, and adversary context.

Data retrieved from Dragos can also be leveraged by Splunk users to build custom searches, reports, detections, correlation rules, and incident response workflows.

The Splunk App is intended to surface Dragos OT data directly inside Splunk so that **SOC teams, OT security engineers, asset owners, and leadership** can monitor and analyze OT risk without requiring direct access to the Dragos user interface.

---

![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active%20development-yellow.svg)

---

## ⚠️ Disclaimer

This application is **not an official Dragos product**.

Use of this software is **not covered** by any license, warranty, or support agreement you may have with Dragos.

All functionality is implemented independently using publicly available Dragos OT API documentation:

https://portal.dragos.com/api/v1/doc/index.html

---

## Supported Operating Environments

Dragos is designed specifically for **Operational Technology (OT)** and **Industrial Control System (ICS)** environments.

The Dragos OT Security for Splunk App reflects this scope and focuses on ingesting and analyzing OT-relevant data only.

---

## OT Domains and Environments Supported

Dragos supports visibility across a wide range of OT environments, including:

- Manufacturing
- Energy and Utilities
- Oil and Gas
- Chemicals
- Transportation
- Water and Wastewater
- Critical Infrastructure
- Industrial Facilities

---

## Industrial Protocol Coverage

Dragos provides native awareness of industrial protocols, including but not limited to:

- Modbus
- DNP3
- EtherNet/IP
- PROFINET
- IEC 61850
- OPC
- BACnet
- ICCP / TASE.2
- Custom and proprietary ICS protocols

Protocol-level telemetry and detections are ingested into Splunk via this app.

---

## Data Collected

### Alerts / Detections

- alert_id
- severity
- confidence
- threat_family
- threat_actor
- tactic / technique
- protocol
- impacted_assets
- recommended_action
- detection_status
- timestamps

---

### Asset Inventory

- asset_id
- ip_address
- mac_address
- vendor
- model
- firmware_version
- asset_type
- zone
- site
- criticality
- first_seen
- last_seen

---

### Network & OT Telemetry

- protocol usage
- anomalous communications
- unexpected connections
- policy violations
- zone-to-zone activity
- asset-to-asset interactions

---

### Threat Intelligence

- adversary name
- campaign
- malware family
- ICS relevance
- kill chain stage
- confidence score
- attribution context

---

## Data Ingestion Model

The Dragos OT Security for Splunk App retrieves data from Dragos using the Dragos REST API.

Data is ingested into a Splunk index specified during configuration.

Each dataset is assigned a predefined sourcetype to ensure consistent parsing, searching, and dashboard functionality.

All events are stored in **JSON format**.

---

## Supported Sourcetypes

| Sourcetype | Description |
|-----------|-------------|
| dragos:alerts | OT alerts and detections |
| dragos:assets | OT asset inventory |
| dragos:network | Network and protocol telemetry |
| dragos:threat_intel | Threat intelligence and adversary data |
| dragos:system | Dragos platform operational logs |

---

## UI → API → Splunk Data Mapping (Authoritative Reference)

This table defines the authoritative mapping between the **Dragos UI**, the
**Dragos REST API**, and the **Splunk data ingested by this app**.

- UI feature → API lineage
- Dashboard and detection data provenance
- Sourcetype ownership and expectations

All mappings are derived from the Dragos Platform Developer Guide.


| Dragos UI Area | UI Functionality | API Endpoint(s) | HTTP Method | Splunk Sourcetype | Primary Fields Ingested |
|---------------|------------------|-----------------|-------------|-------------------|-------------------------|
| Overview | Platform posture summary | `/api/v1/alerts` | GET | `dragos:alerts` | severity, confidence, status |
| Overview | Asset population summary | `/api/v1/assets` | GET | `dragos:assets` | asset_id, criticality |
| Alerts / Detections | Active threat detections | `/api/v1/alerts` | GET | `dragos:alerts` | alert_id, threat_family, impacted_assets |
| Alerts / Detections | Alert lifecycle state | `/api/v1/alerts/{id}` | GET | `dragos:alerts` | acknowledged, resolved, timestamps |
| Assets | OT asset inventory | `/api/v1/assets` | GET | `dragos:assets` | ip, mac, vendor, model |
| Assets | Asset metadata | `/api/v1/assets/{id}` | GET | `dragos:assets` | zone, site, first_seen, last_seen |
| Vulnerabilities | Vulnerability inventory | `/api/v1/vulnerabilities` | GET | `dragos:vulnerabilities` | vuln_id, severity, cve |
| Vulnerabilities | Asset vulnerability mapping | `/api/v1/vulnerabilities/assets` | GET | `dragos:vulnerabilities` | asset_id, vuln_id |
| Vulnerabilities | Vulnerability details | `/api/v1/vulnerabilities/{id}` | GET | `dragos:vulnerabilities` | description, remediation |
| Network Activity | OT communications | `/api/v1/communications` | GET | `dragos:network` | protocol, src, dst |
| Network Activity | Protocol usage | `/api/v1/protocols` | GET | `dragos:network` | protocol_name, volume |
| Network Activity | Anomalies | `/api/v1/anomalies` | GET | `dragos:network` | anomaly_type, severity |
| Threat Intelligence | Adversary profiles | `/api/v1/adversaries` | GET | `dragos:threatintel` | name, motivation |
| Threat Intelligence | Campaigns | `/api/v1/campaigns` | GET | `dragos:threatintel` | campaign_name, start_date |
| Threat Intelligence | Malware families | `/api/v1/malware` | GET | `dragos:threatintel` | family, behavior |
| Threat Intelligence | Kill chain mapping | `/api/v1/threats` | GET | `dragos:threatintel` | stage, confidence |
| Reporting | Historical alert trends | `/api/v1/alerts` | GET | `dragos:alerts` | timestamps, severity |
| Reporting | Vulnerability trends | `/api/v1/vulnerabilities` | GET | `dragos:vulnerabilities` | severity, discovery_date |
| Operations | Platform version | `/api/v1/version` | GET | `dragos:meta` | version, build |
| Operations | System health | `/api/v1/status` | GET | `dragos:meta` | uptime, component_state |

---

### Notes

- All data is ingested as **raw JSON** to preserve fidelity.
- No UI scraping is performed; **all data originates from documented APIs**.
- Dashboards, detections, and executive views are built exclusively from these sourcetypes.
- Vulnerabilities are treated as **first-class security data**, not derivative artifacts.

## Dashboards

| Dashboard | Description |
|----------|-------------|
| 🧭 Overview | High-level OT security posture |
| 🚨 Alerts | Active detections and severity trends |
| 🖥️ Assets | OT asset inventory and criticality |
| 🌐 Network | Protocol and behavioral analytics |
| 🧠 Threat Intelligence | Adversary activity and campaigns |

---

## Installation

### Step 1: Install the App

1. Download the Dragos OT Security for Splunk App package
2. In Splunk Web, navigate to **Apps → Manage Apps**
3. Select **Install app from file**
4. Upload the application package
5. Restart Splunk if prompted

---

### Step 2: Configure the App

1. Open the **Dragos OT Security** app
2. Navigate to **Settings → Configuration**
3. Configure:
   - Dragos API base URL
   - API key
   - Target Splunk index
   - Proxy settings (optional)
   - Polling interval
4. Save configuration

---

### Step 3: Verify Data Collection

Run the following search to confirm ingestion:


---

## Directory Structure
```
Dragos_OT_Security_For_Splunk_App/
├── app.manifest
├── LICENSE
├── README.md
├── default/
│   ├── app.conf
│   ├── inputs.conf
│   ├── props.conf
│   ├── transforms.conf
│   ├── macros.conf
│   ├── restmap.conf
│   ├── savedsearches.conf
│   ├── web.conf
│   └── data/
│       └── ui/
│           ├── nav/
│           │   └── default.xml
│           └── views/
│               ├── setup.xml
│               ├── dragos_overview.xml
│               ├── dragos_alerts.xml
│               ├── dragos_assets.xml
│               ├── dragos_network.xml
│               ├── dragos_threat_intel.xml
│               ├── dragos_reports.xml
│               └── dragos_help.xml
├── bin/
│   ├── dragos_input.py
│   ├── dragos_setup_handler.py
│   └── dragos_validation.py
├── metadata/
│   ├── default.meta
│   └── local.meta
└── static/
├── appIcon.png
└── appIcon_2x.png

```
---

## Requirements

- Splunk Enterprise or Splunk Cloud (Classic Experience)
- Network connectivity to Dragos platform
- Valid Dragos API credentials
- Operational Dragos deployment

---

## AppInspect Compliance

- Standard Splunk app directory structure
- Inputs disabled by default
- Secure credential handling
- No hardcoded secrets
- JSON-based ingestion
- MIT License

---

## References

- Dragos product documentation  
  https://www.dragos.com

- Dragos API documentation  
  https://portal.dragos.com/api/v1/doc/index.html

- Splunk documentation  
  https://docs.splunk.com

---

## MIT License

Copyright (c) 2026 Mark Teicher

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
