# Dragos OT Security for Splunk

Dashboards and API-driven data ingestion for **Dragos OT Security** telemetry, alerts, assets, network activity, and threat intelligence in Splunk.

---

## ⚠️ Disclaimer

This application is **not an official Dragos product**.

Use of this software is **not covered** by any license, warranty, or support agreement you may have with Dragos.  
All functionality is implemented independently using publicly available Dragos OT API documentation:

https://portal.dragos.com/api/v1/doc/index.html

---

## Overview

The **Dragos OT Security for Splunk App** provides:

- Native Splunk dashboards for Dragos OT data
- API-based ingestion of Dragos telemetry
- Structured indexes and sourcetypes
- Operational visibility into OT alerts, assets, network behavior, and adversary activity

---

## Data Collected

### Alerts / Detections
- alert_id
- severity
- confidence
- threat_family
- threat_actor
- protocol
- impacted_assets
- recommended_action
- timestamps and status

### Asset / Inventory
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

### Network & OT Telemetry
- protocol usage (Modbus, DNP3, EtherNet/IP, etc.)
- anomalous communications
- unexpected connections
- policy violations
- zone-to-zone activity

### Threat Intelligence
- adversary names
- campaigns
- malware families
- ICS specificity
- kill chain stage
- confidence scores

---

## Dashboards Included

- **Overview** – High-level OT security posture
- **Alerts** – Active detections and severity trends
- **Assets** – OT asset inventory and criticality
- **Network & OT Telemetry** – Behavioral and protocol analytics
- **Threat Intelligence** – Adversary activity and campaigns

---

## Installation

### Supported Platforms
- Splunk Enterprise 8.x+
- Splunk Enterprise 9.x
- Splunk Cloud (Classic Experience)

---

### Installation Package

The application is distributed as:

- `DRAGOS-OT-Splunk-App.spl`
- or `DRAGOS-OT-Splunk-App.tar.gz`

A `.spl` file is a `.tar.gz` archive with a different extension.

---

### Install via Splunk Web

Apps → Manage Apps → Install app from file → Upload → Restart if prompted

---

### Install via CLI

$SPLUNK_HOME/bin/splunk install app DRAGOS-OT-Splunk-App.spl  
$SPLUNK_HOME/bin/splunk restart

---

## Configuration

After installation:

1. Open the **Dragos OT Security** app
2. Go to **Settings → Configuration**
3. Configure API base URL, API key, index, proxy (optional), interval
4. Save

---

## Verification

Example searches:

index=<dragos_index> sourcetype=dragos:alerts  
index=<dragos_index> sourcetype=dragos:assets  
index=<dragos_index> sourcetype=dragos:network_telemetry  
index=<dragos_index> sourcetype=dragos:threat_intel  

---

## License

MIT License  
© Mark Teicher
