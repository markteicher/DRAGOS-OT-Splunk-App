# Dragos OT Security for Splunk

A Splunk **application** that provides dashboards and data ingestion support for **Dragos OT Security** telemetry, alerts, assets, network activity, and threat intelligence.

This app is designed to visualize Dragos OT data that has been ingested into Splunk using Dragos APIs and modular inputs.

---

## ⚠️ Disclaimer

This application is **not an official Dragos product**.

Use of this software is **not covered** by any license, warranty, or support agreement with Dragos.  
All functionality is implemented independently using **publicly available Dragos OT API documentation**:

https://portal.dragos.com/api/v1/doc/index.html

---

## Overview

The **Dragos OT Security for Splunk App** provides:

- Prebuilt Splunk Classic dashboards
- Standardized index and sourcetype expectations
- Modular input definitions for Dragos API ingestion
- Visualizations aligned with the Dragos platform UI

The app focuses on **operational visibility**, not configuration or control-plane management.

---

## Supported Data Types

This app is designed to work with the following Dragos OT data categories:

### Alerts / Detections
- Severity
- Confidence
- Threat family / actor (when available)
- Impacted assets
- Recommended actions

### Assets / Inventory
- OT assets (PLC, HMI, servers, controllers)
- Vendor, model, firmware
- Zone and site context
- First seen / last seen timestamps

### Network & OT Telemetry
- Protocol usage (Modbus, DNP3, EtherNet/IP, etc.)
- Anomalous communications
- Policy violations
- Zone-to-zone activity

### Threat Intelligence
- Adversary activity
- Campaign indicators
- ICS-specific threat context
- Kill-chain stage alignment

---

## Dashboards Included

- **Overview** – High-level OT security posture
- **Alerts** – Detection and alert activity
- **Assets** – OT asset inventory and context
- **Network & OT Telemetry** – Communications and anomalies
- **Threat Intelligence** – Adversary and campaign visibility

All dashboards are implemented using **Splunk Classic XML**.

---

## Data Ingestion

This app supports **API-based ingestion** using modular inputs.

Inputs are defined in:
- `inputs.conf`
- `inputs.conf.spec`

Each input supports:
- API base URL
- API key
- Index selection
- Proxy configuration
- SSL verification
- Polling interval

This app **does not ship with credentials** and does not auto-configure inputs.

---

## Installation

1. Install the app into Splunk:
   ```bash
   $SPLUNK_HOME/etc/apps/dragos_ot_security
