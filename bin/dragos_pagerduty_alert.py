#!/usr/bin/env python
# encoding: utf-8
"""
Dragos PagerDuty Alert Action
Triggers PagerDuty incidents for Dragos alerts and notifications
"""

import sys
import os
import json
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

try:
    import requests
except ImportError:
    import urllib.request
    import urllib.error
    requests = None


PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


def substitute_variables(template, payload):
    """
    Substitute $variable$ patterns with values from the Splunk alert payload.
    No assumptions are made about Dragos field names.
    """

    result = payload.get("result", {})

    substitutions = {
        "name": payload.get("search_name", ""),
        "search_name": payload.get("search_name", ""),
        "trigger_time": payload.get("trigger_time", ""),
        "app": payload.get("app", "dragos"),
        "owner": payload.get("owner", ""),
        "results_link": payload.get("results_link", ""),
    }

    # Include all result fields as result.<field>
    for key, value in result.items():
        substitutions[f"result.{key}"] = str(value) if value is not None else ""

    def replace(match):
        var = match.group(1)
        return substitutions.get(var, match.group(0))

    return re.sub(r"\$([^$]+)\$", replace, template)


def send_pagerduty_event(config, payload):
    """Send event to PagerDuty"""

    routing_key = config.get("routing_key", "")
    severity = config.get("severity", "error")
    dedup_key = config.get("dedup_key", "")
    event_action = config.get("event_action", "trigger")
    summary = config.get("summary", "Dragos Alert")
    source = config.get("source", "Splunk Dragos App")
    component = config.get("component", "")
    group = config.get("group", "ot-security")
    event_class = config.get("class", "dragos-alert")

    if not routing_key:
        return False, "No PagerDuty routing key configured"

    # Variable substitution
    summary = substitute_variables(summary, payload)
    dedup_key = substitute_variables(dedup_key, payload)
    component = substitute_variables(component, payload)

    pd_payload = {
        "routing_key": routing_key,
        "event_action": event_action,
        "dedup_key": dedup_key if dedup_key else None,
        "payload": {
            "summary": summary,
            "severity": severity,
            "source": source,
            "component": component if component else None,
            "group": group,
            "class": event_class,
            "custom_details": {
                "search_name": payload.get("search_name", ""),
                "trigger_time": payload.get("trigger_time", ""),
                "results_link": payload.get("results_link", ""),
                "result": payload.get("result", {}),
            },
        },
    }

    # Strip None values
    pd_payload = {k: v for k, v in pd_payload.items() if v is not None}
    pd_payload["payload"] = {
        k: v for k, v in pd_payload["payload"].items() if v is not None
    }

    headers = {"Content-Type": "application/json"}

    try:
        if requests:
            response = requests.post(
                PAGERDUTY_EVENTS_URL,
                json=pd_payload,
                headers=headers,
                timeout=30,
            )

            if response.status_code >= 400:
                return False, f"PagerDuty returned {response.status_code}: {response.text}"

            resp = response.json()
            return True, f"PagerDuty event created: {resp.get('dedup_key', 'unknown')}"

        else:
            data = json.dumps(pd_payload).encode("utf-8")
            req = urllib.request.Request(
                PAGERDUTY_EVENTS_URL, data=data, headers=headers
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                if response.getcode() >= 400:
                    return False, f"PagerDuty returned status {response.getcode()}"
                resp = json.loads(response.read().decode("utf-8"))
                return True, f"PagerDuty event created: {resp.get('dedup_key', 'unknown')}"

    except Exception as e:
        return False, f"PagerDuty request failed: {str(e)}"


def main():
    """Splunk alert action entry point"""

    if len(sys.argv) < 2:
        print("ERROR: No payload file provided", file=sys.stderr)
        sys.exit(1)

    payload_file = sys.argv[1]

    try:
        with open(payload_file, "r") as fh:
            payload = json.load(fh)
    except Exception as e:
        print(f"ERROR: Failed to read payload: {e}", file=sys.stderr)
        sys.exit(1)

    config = payload.get("configuration", {})

    success, message = send_pagerduty_event(config, payload)

    if success:
        print(f"INFO: {message}")
        sys.exit(0)
    else:
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
