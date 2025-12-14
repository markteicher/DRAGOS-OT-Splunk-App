# inputs.conf.spec
#
# Dragos OT Security for Splunk
# Modular Input Specifications
#
# These inputs ingest Dragos OT data via the Dragos REST API.
# Credentials are expected to be stored securely.
#

[dragos_alerts://<name>]
description = Collect Dragos alert and detection events
base_url = <string>
api_key = <string> (encrypted)
index = <string>
sourcetype = dragos:alerts
proxy = <string>
verify_ssl = <boolean> (default: true)
interval = <number> (default: 300)
disabled = <boolean> (default: false)

[dragos_assets://<name>]
description = Collect Dragos OT asset and inventory data
base_url = <string>
api_key = <string> (encrypted)
index = <string>
sourcetype = dragos:assets
proxy = <string>
verify_ssl = <boolean> (default: true)
interval = <number> (default: 3600)
disabled = <boolean> (default: false)

[dragos_threat_intel://<name>]
description = Collect Dragos adversary and threat intelligence data
base_url = <string>
api_key = <string> (encrypted)
index = <string>
sourcetype = dragos:threat_intel
proxy = <string>
verify_ssl = <boolean> (default: true)
interval = <number> (default: 1800)
disabled = <boolean> (default: false)

[dragos_network_telemetry://<name>]
description = Collect summarized Dragos OT network telemetry
base_url = <string>
api_key = <string> (encrypted)
index = <string>
sourcetype = dragos:network_telemetry
proxy = <string>
verify_ssl = <boolean> (default: true)
interval = <number> (default: 300)
disabled = <boolean> (default: false)
