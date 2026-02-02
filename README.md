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
