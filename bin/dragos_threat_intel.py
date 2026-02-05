#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =========================================================================
# File: bin/dragos_threat_intel.py
#
# Dragos OT Security for Splunk App
#
# PURPOSE
# -------
# Collect Dragos WorldView threat intelligence metadata.
#
# This input collects high-level threat intelligence objects such as:
# - Activity groups
# - Campaigns
# - Threat reports
# - Malware / tooling metadata
#
#
# =========================================================================

import sys
import os
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import splunklib.modularinput as smi


# -------------------------------------------------------------------------
# Utility helpers
# -------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_checkpoint(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def write_checkpoint(path: str, data: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def dump_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


# -------------------------------------------------------------------------
# Dragos API client
# -------------------------------------------------------------------------

class DragosThreatIntelClient:
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

    def get_threat_intel(
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
            f"{self.base_url}/api/v1/threat-intel",
            params=params,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()


# -------------------------------------------------------------------------
# Modular Input
# -------------------------------------------------------------------------

class DragosThreatIntelInput(smi.Script):

    def get_scheme(self):
        scheme = smi.Scheme("Dragos Threat Intelligence Input")
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
        p = definition.parameters
        client = DragosThreatIntelClient(
            base_url=p["dragos_url"],
            api_token=p["api_token"],
            timeout=int(p.get("timeout") or 60),
            verify_ssl=p.get("verify_ssl", True),
            proxy=p.get("proxy"),
        )
        client.get_threat_intel(
            page=1,
            page_size=1,
            updated_after="1970-01-01T00:00:00Z",
        )

    def stream_events(self, inputs, ew):
        ew.log(smi.LogLevel.INFO, "Dragos Threat Intel input starting")

        for stanza, cfg in inputs.inputs.items():
            params = cfg["params"]
            ckpt_path = os.path.join(cfg["checkpoint_dir"], f"{stanza}.json")
            checkpoint = read_checkpoint(ckpt_path)

            updated_after = checkpoint.get(
                "updated_after", "1970-01-01T00:00:00Z"
            )

            client = DragosThreatIntelClient(
                base_url=params["dragos_url"],
                api_token=params["api_token"],
                timeout=int(params.get("timeout") or 60),
                verify_ssl=params.get("verify_ssl", True),
                proxy=params.get("proxy"),
            )

            page = 1
            page_size = int(params.get("page_size") or 200)
            newest_seen = updated_after
            count = 0

            while True:
                payload = client.get_threat_intel(
                    page=page,
                    page_size=page_size,
                    updated_after=updated_after,
                )

                objects = payload.get("results", [])
                if not objects:
                    break

                for obj in objects:
                    ew.write_event(
                        smi.Event(
                            data=dump_json(obj),
                            sourcetype="dragos:threat_intel",
                        )
                    )
                    count += 1

                    ts = obj.get("updated_at")
                    if ts and ts > newest_seen:
                        newest_seen = ts

                if page >= payload.get("total_pages", 1):
                    break

                page += 1

            checkpoint["updated_after"] = newest_seen
            write_checkpoint(ckpt_path, checkpoint)

            ew.log(
                smi.LogLevel.INFO,
                f"Threat intel collection complete — events={count}, checkpoint={newest_seen}",
            )

        ew.log(smi.LogLevel.INFO, "Dragos Threat Intel input completed")


if __name__ == "__main__":
    sys.exit(DragosThreatIntelInput().run(sys.argv))
