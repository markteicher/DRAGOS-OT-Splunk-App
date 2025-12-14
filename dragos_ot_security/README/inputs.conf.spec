# inputs.conf.spec
#
# Specification file for Dragos OT Security for Splunk
# Modular inputs for Dragos API ingestion
#

[dragos_alerts://<name>]
description = Collect Dragos alert / detection events via Dragos API
base_url = <string>
api_key = <string>
index = <string>
proxy = <string>
verify_ssl = <boolean>
timeout = <number>
interval = <number>
disabled = <boolean>

[dragos_assets://<name>]
description = Collect Dragos asset / inventory data
base_url = <string>
api_key = <string>
index = <string>
proxy = <string>
verify_ssl = <boolean>
timeout = <number>
interval = <number>
disabled = <boolean>

[dragos_threat_intel://<name>]
description = Collect Dragos adversary / threat intelligence data
base_url = <string>
api_key = <string>
index = <string>
proxy = <string>
verify_ssl = <boolean>
timeout = <number>
interval = <number>
disabled = <boolean>

[dragos_network_telemetry://<name>]
description = Collect Dragos summarized network / OT telemetry
base_url = <string>
api_key = <string>
index = <string>
proxy = <string>
verify_ssl = <boolean>
timeout = <number>
interval = <number>
disabled = <boolean>
