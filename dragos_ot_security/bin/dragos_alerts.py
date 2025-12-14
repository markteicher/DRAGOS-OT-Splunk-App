#!/usr/bin/env python3
"""
Dragos Alerts Modular Input

Collects Dragos alert / detection events and writes them to Splunk
with proper index, sourcetype, and checkpointing.

Depends on:
    bin/lib/dragos_client.py
"""

import sys
import os
import json
import time
from datetime import datetime, timezone

from splunklib.modularinput import (
    Script,
    Scheme,
    Argument,
    Event,
    EventWriter,
)

from lib.dragos_client import DragosClient, DragosAPIError


CHECKPOINT_KEY = "dragos_alerts_last_ts"
DEFAULT_LOOKBACK_SECONDS = 300  # 5 minutes safety buffer


class DragosAlertsInput(Script):
    # ------------------------------------------------------------------
    # SCHEME
    # ------------------------------------------------------------------

    def get_scheme(self):
        scheme = Scheme("Dragos Alerts")
        scheme.description = "Collect Dragos alert / detection events"
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = False

        scheme.add_argument(Argument(
            name="base_url",
            title="Dragos API Base URL",
            data_type=Argument.data_type_string,
            required_on_create=True,
        ))

        scheme.add_argument(Argument(
            name="api_key",
            title="Dragos API Key",
            data_type=Argument.data_type_string,
            required_on_create=True,
        ))

        scheme.add_argument(Argument(
            name="index",
            title="Splunk Index",
            data_type=Argument.data_type_string,
            required_on_create=True,
        ))

        scheme.add_argument(Argument(
            name="proxy",
            title="Proxy URL (optional)",
            data_type=Argument.data_type_string,
            required_on_create=False,
        ))

        scheme.add_argument(Argument(
            name="verify_ssl",
            title="Verify SSL",
            data_type=Argument.data_type_boolean,
            required_on_create=False,
        ))

        return scheme

    # ------------------------------------------------------------------
    # STREAM EVENTS
    # ------------------------------------------------------------------

    def stream_events(self, inputs, ew: EventWriter):
        for input_name, params in inputs.inputs.items():
            base_url = params["base_url"]
            api_key = params["api_key"]
            index = params["index"]
            proxy = params.get("proxy")
            verify_ssl = params.get("verify_ssl", True)

            # -------------------------------
            # Checkpoint handling
            # -------------------------------
            checkpoint = self._get_checkpoint(input_name)
            if checkpoint:
                since_ts = checkpoint
            else:
                since_ts = (
                    datetime.now(timezone.utc)
                    .timestamp()
                    - DEFAULT_LOOKBACK_SECONDS
                )
                since_ts = datetime.fromtimestamp(
                    since_ts, tz=timezone.utc
                ).isoformat()

            # -------------------------------
            # Client
            # -------------------------------
            client = DragosClient(
                base_url=base_url,
                api_key=api_key,
                proxy=proxy,
                verify_ssl=verify_ssl,
            )

            try:
                alerts = client.collect_since(
                    endpoint="/api/v1/alerts",
                    since_ts=since_ts,
                    items_key="alerts",
                )
            except DragosAPIError as exc:
                ew.log(EventWriter.ERROR, f"Dragos API error: {exc}")
                return

            latest_ts = since_ts

            for alert in alerts:
                event_time = alert.get("timestamp") or alert.get("created_at")

                if event_time:
                    latest_ts = max(latest_ts, event_time)

                ew.write_event(Event(
                    data=json.dumps(alert),
                    sourcetype="dragos:alert",
                    index=index,
                    time=self._parse_time(event_time),
                ))

            # -------------------------------
            # Save checkpoint
            # -------------------------------
            self._save_checkpoint(input_name, latest_ts)

    # ------------------------------------------------------------------
    # CHECKPOINT UTILITIES
    # ------------------------------------------------------------------

    def _get_checkpoint(self, input_name):
        return self.service.kvstore[self._ckey(input_name)]

    def _save_checkpoint(self, input_name, value):
        self.service.kvstore[self._ckey(input_name)] = value

    def _ckey(self, input_name):
        return f"{CHECKPOINT_KEY}:{input_name}"

    # ------------------------------------------------------------------
    # TIME PARSING
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_time(ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            return None


if __name__ == "__main__":
    sys.exit(DragosAlertsInput().run(sys.argv))
