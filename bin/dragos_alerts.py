#!/usr/bin/env python3
#
# dragos_alerts.py
#
# Splunk modular input for Dragos OT Alerts / Detections
#

import sys
import json
import logging
import time
from typing import Dict

import splunklib.modularinput as smi

from lib.dragos_client import DragosAPIClient


class DragosAlertsInput(smi.Script):
    """
    Modular input for Dragos alert / detection events.
    """

    def get_scheme(self):
        scheme = smi.Scheme("Dragos Alerts")
        scheme.description = "Collect Dragos OT alert and detection events"
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        scheme.add_argument(smi.Argument(
            name="base_url",
            description="Dragos API base URL",
            required_on_create=True,
        ))

        scheme.add_argument(smi.Argument(
            name="api_key",
            description="Dragos API key",
            required_on_create=True,
        ))

        scheme.add_argument(smi.Argument(
            name="index",
            description="Splunk index to write events to",
            required_on_create=True,
        ))

        scheme.add_argument(smi.Argument(
            name="proxy",
            description="Optional proxy URL",
            required_on_create=False,
        ))

        scheme.add_argument(smi.Argument(
            name="verify_ssl",
            description="Verify SSL certificates (true/false)",
            required_on_create=False,
        ))

        return scheme

    # ------------------------------------------------------------------
    def validate_input(self, definition):
        """
        Basic validation of required fields.
        """
        params = definition.parameters
        if not params.get("base_url"):
            raise ValueError("base_url is required")
        if not params.get("api_key"):
            raise ValueError("api_key is required")

    # ------------------------------------------------------------------
    def stream_events(self, inputs, ew):
        """
        Main ingestion loop.
        """
        for input_name, input_item in inputs.inputs.items():
            params = input_item

            base_url = params.get("base_url")
            api_key = params.get("api_key")
            index = params.get("index")
            proxy = params.get("proxy")
            verify_ssl = params.get("verify_ssl", "true").lower() == "true"

            client = DragosAPIClient(
                base_url=base_url,
                api_key=api_key,
                proxy=proxy,
                verify_ssl=verify_ssl,
            )

            for alert in client.get_alerts():
                event = smi.Event(
                    data=json.dumps(alert),
                    index=index,
                    sourcetype="dragos:alert",
                    time=self._extract_time(alert),
                )
                ew.write_event(event)

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_time(alert: Dict):
        """
        Extract event time from Dragos alert.
        """
        return alert.get("timestamp") or time.time()


if __name__ == "__main__":
    DragosAlertsInput().run(sys.argv)
