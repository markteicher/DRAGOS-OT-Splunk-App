#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
/bin/dragos_input.py

Dragos OT Security for Splunk App
Primary Modular Input Dispatcher

===============================================================================
PURPOSE
===============================================================================

This file serves as the **single entry point dispatcher** for all Dragos
modular inputs within the Dragos OT Security for Splunk App.


It DOES:
- Register modular input types with Splunk

===============================================================================
SUPPORTED DATA DOMAINS
===============================================================================

Each domain is implemented in its own dedicated module under /bin
and follows a strict one-object → one-event model.

1. Threat Intelligence (Worldview)
   - Indicators / IOCs
   - Source: GET /api/v1/indicators
   - Module: input_module_iocs.py
   - Sourcetype: dragos:indicators

2. Vulnerability Intelligence
   - OT vulnerabilities and advisories
   - Source: GET /api/v1/vulnerabilities
   - Module: dragos_vulnerabilities.py
   - Sourcetype: dragos:vulnerabilities

3. Alerts & Notifications
   - Operational alerts, detections, system events
   - Source: /notifications/api/v2/notification
   - Module: input_module_notifications.py
   - Sourcetype: dragos:alerts

4. Asset Inventory
   - Assets, metadata, hardware identity
   - Source: /assets/api/v4/getAssets
   - Module: input_module_asset_data.py
   - Sourcetype: dragos:assets

5. Asset Addresses
   - IP, MAC, DNS, hostname associations
   - Source: /assets/api/v4/getAddresses
   - Module: input_module_addresses.py
   - Sourcetype: dragos:addresses

6. Asset Zones
   - Logical and network zoning
   - Source: /assets/api/v4/getZones
   - Module: input_module_asset_zones.py
   - Sourcetype: dragos:zones

===============================================================================
ARCHITECTURAL GUARANTEES
===============================================================================

- One Splunk event per API object
- Full JSON payload preserved
- No field normalization in this layer
- No severity scoring
- Timestamp logic is delegated to the responsible module

===============================================================================
ERROR HANDLING
===============================================================================

- Input validation is delegated to each module
- API retry, pagination, and backoff logic is module-owned
- Dispatcher fails fast if module registration

===============================================================================
CHANGE POLICY
===============================================================================

This file should only change when:
- A new Dragos data domain is added
- A modular input is removed
- A domain-level contract changes

===============================================================================
"""

# NOTE:
# This file intentionally contains minimal executable code.
# All collection logic lives in domain-specific input modules.
#
# The presence of this file is primarily architectural and declarative.
#
