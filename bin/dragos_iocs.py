#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =========================================================================
# File: bin/dragos_iocs.py
#
# Dragos OT Security for Splunk App
#
# PURPOSE
# -------
# Collect raw Indicator of Compromise (IOC) data from Dragos WorldView.
#
# - Endpoint: GET /api/v1/indicators
# - Emits raw JSON events
# - Incremental collection via updated_after timestamp
# 
#
# 
#
# =========================================================================

import sys
import os
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import splunklib.modularinput as smi


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_checkpoint(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_checkpoint(path: str, data: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def to_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


# -------------------------------------------------------------------------
# Dragos API Client (IOC-specific)
# -------------------------------------------------------------------------

class DragosIOCClient:
    def __init__(
        self,
        base_url: str,
        api_token: str,
        timeout: int,
        verify_ssl: bool,
        proxy: Optional[str],
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Accept": "application/json",
            "Authorization": f"Bearer {api_token}",
        })

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        retry = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=["GET"],
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def get_indicators(
        self,
        page: int,
        page_size: int,
        updated_after: str,
    ) -> Dict[str, Any]:
        params = {
            "page": page,
            "page_size": page_size,
            "updated_after": updated_after,
        }
        resp = self.session.get(
            f"{self.base_url}/api/v1/indicators",
            params=params,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()


# -------------------------------------------------------------------------
# Modular Input
# -------------------------------------------------------------------------

class DragosIOCsInput(smi.Script):

    def get_scheme(self):
        scheme = smi.Scheme("Dragos IOC Input")
        scheme.use_external_validation = True

        scheme.add_argument(smi.Argument(
            "dragos_url", "Dragos Base URL",
            smi.Argument.data_type_string, True
        ))
        scheme.add_argument(smi.Argument(
            "api_token", "API Token",
            smi.Argument.data_type_string, True, encrypted=True
        ))
        scheme.add_argument(smi.Argument(
            "verify_ssl", "Verify SSL",
            smi.Argument.data_type_boolean, False
        ))
        scheme.add_argument(smi.Argument(
            "timeout", "HTTP Timeout",
            smi.Argument.data_type_number, False
        ))
        scheme.add_argument(smi.Argument(
            "proxy", "Proxy URL",
            smi.Argument.data_type_string, False
        ))
        scheme.add_argument(smi.Argument(
            "page_size", "Page Size",
            smi.Argument.data_type_number, False
        ))

        return scheme

    def validate_input(self, definition):
        # Minimal validation: endpoint reachability
        p = definition.parameters
        client = DragosIOCClient(
            base_url=p["dragos_url"],
            api_token=p["api_token"],
            timeout=int(p.get("timeout") or 60),
            verify_ssl=p.get("verify_ssl", True),
            proxy=p.get("proxy"),
        )
        client.get_indicators(page=1, page_size=1, updated_after="1970-01-01T00:00:00Z")

    def stream_events(self, inputs, ew):
        ew.log(smi.LogLevel.INFO, "Dragos IOC input starting")

        for stanza, cfg in inputs.inputs.items():
            params = cfg["params"]
            ckpt_file = os.path.join(cfg["checkpoint_dir"], f"{stanza}.json")
            checkpoint = load_checkpoint(ckpt_file)

            updated_after = checkpoint.get(
                "updated_after", "1970-01-01T00:00:00Z"
            )

            client = DragosIOCClient(
                base_url=params["dragos_url"],
                api_token=params["api_token"],
                timeout=int(params.get("timeout") or 60),
                verify_ssl=params.get("verify_ssl", True),
                proxy=params.get("proxy"),
            )

            page = 1
            page_size = int(params.get("page_size") or 500)
            max_seen_timestamp = updated_after
            total_events = 0

            while True:
                data = client.get_indicators(
                    page=page,
                    page_size=page_size,
                    updated_after=updated_after,
                )

                indicators = data.get("indicators", [])
                if not indicators:
                    break

                for indicator in indicators:
                    ew.write_event(
                        smi.Event(
                            data=to_json(indicator),
                            sourcetype="dragos:indicators",
                        )
                    )
                    total_events += 1

                    ts = indicator.get("updated_at")
                    if ts and ts > max_seen_timestamp:
                        max_seen_timestamp = ts

                if page >= data.get("total_pages", 1):
                    break

                page += 1

            checkpoint["updated_after"] = max_seen_timestamp
            save_checkpoint(ckpt_file, checkpoint)

            ew.log(
                smi.LogLevel.INFO,
                f"Dragos IOC collection complete — events={total_events}, checkpoint={max_seen_timestamp}",
            )

        ew.log(smi.LogLevel.INFO, "Dragos IOC input completed successfully")


if __name__ == "__main__":
    sys.exit(DragosIOCsInput().run(sys.argv))
