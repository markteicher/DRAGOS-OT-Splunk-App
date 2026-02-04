#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# File: bin/dragos_input.py
# -------------------------------------------------------------------------
# Dragos OT Security for Splunk App – Modular Input
#
# Implementation notes
#
# - Authentication:
#     * Static API token (Dragos REST APIs)
#     * Token passed via Authorization header
#
# - Proxy support:
#     * no proxy
#     * proxy without authentication
#     * proxy with username/password authentication
#
# - Logging:
#     * Unix-style informational logging via Splunk event writer (ew.log)
#     * no stdout printing
#
# - Collectors:
#     * strict read-only collectors only (GET endpoints)
#
# - Collection model:
#     * inventory-style collectors (assets, vulnerabilities, notifications)
#
# - Pagination:
#     * pageNumber / pageSize model
#
# - HTTP resiliency:
#     * retries with backoff for transient failures (429 / 5xx)
#
# - Splunk AppInspect compliance:
#     * no file-based logging
# -------------------------------------------------------------------------

import json
import os
import sys
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import splunklib.modularinput as smi


def to_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


class DragosAPI:
    def __init__(
        self,
        base_url: str,
        api_token: str,
        log,
        verify_ssl: bool = True,
        timeout: int = 60,
        proxy_url: Optional[str] = None,
        proxy_user: Optional[str] = None,
        proxy_pass: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self.log = log

        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_token}",
            }
        )

        retry = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=["GET"],
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

        if proxy_url:
            proxy = proxy_url
            if proxy_user and proxy_pass:
                proxy = proxy_url.replace(
                    "://", f"://{proxy_user}:{proxy_pass}@", 1
                )
            self.session.proxies = {"http": proxy, "https": proxy}

    def get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        resp = self.session.get(
            url,
            params=params or {},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()


class DragosInput(smi.Script):
    def get_scheme(self):
        scheme = smi.Scheme("Dragos OT Security Input")
        scheme.use_external_validation = True

        scheme.add_argument(
            smi.Argument(
                "dragos_url",
                "Dragos Base URL",
                smi.Argument.data_type_string,
                True,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "api_token",
                "API Token",
                smi.Argument.data_type_string,
                True,
                encrypted=True,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "verify_ssl",
                "Verify SSL",
                smi.Argument.data_type_boolean,
                False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "timeout",
                "Timeout",
                smi.Argument.data_type_number,
                False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "proxy_url",
                "Proxy URL",
                smi.Argument.data_type_string,
                False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "proxy_user",
                "Proxy Username",
                smi.Argument.data_type_string,
                False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "proxy_pass",
                "Proxy Password",
                smi.Argument.data_type_string,
                False,
                encrypted=True,
            )
        )

        return scheme

    def validate_input(self, definition):
        p = definition.parameters
        api = DragosAPI(
            p["dragos_url"],
            p["api_token"],
            log=lambda *_: None,
            verify_ssl=p.get("verify_ssl", True),
            timeout=int(p.get("timeout") or 60),
            proxy_url=p.get("proxy_url"),
            proxy_user=p.get("proxy_user"),
            proxy_pass=p.get("proxy_pass"),
        )
        api.get("/api/v2/assets", params={"pageSize": 1, "pageNumber": 1})

    def stream_events(self, inputs, ew):
        ew.log(smi.LogLevel.INFO, "Dragos input starting")

        for stanza, cfg in inputs.inputs.items():
            params = cfg["params"]

            api = DragosAPI(
                params["dragos_url"],
                params["api_token"],
                log=ew.log,
                verify_ssl=params.get("verify_ssl", True),
                timeout=int(params.get("timeout") or 60),
                proxy_url=params.get("proxy_url"),
                proxy_user=params.get("proxy_user"),
                proxy_pass=params.get("proxy_pass"),
            )

            # ----------------------------------------------------------
            # Assets
            # ----------------------------------------------------------
            ew.log(smi.LogLevel.INFO, "Collecting assets")
            page = 1
            page_size = 100

            while True:
                resp = api.get(
                    "/api/v2/assets",
                    params={"pageSize": page_size, "pageNumber": page},
                )
                assets = resp.get("content", [])
                for asset in assets:
                    ew.write_event(
                        smi.Event(
                            to_json(asset),
                            sourcetype="dragos:assets",
                        )
                    )

                if len(assets) < page_size:
                    break
                page += 1

            ew.log(smi.LogLevel.INFO, "Asset collection completed")

            # ----------------------------------------------------------
            # Vulnerabilities
            # ----------------------------------------------------------
            ew.log(smi.LogLevel.INFO, "Collecting vulnerabilities")
            vulns = api.get("/api/v1/vulnerabilities")
            for v in vulns:
                ew.write_event(
                    smi.Event(
                        to_json(v),
                        sourcetype="dragos:vulnerabilities",
                    )
                )
            ew.log(
                smi.LogLevel.INFO,
                f"Collected {len(vulns)} vulnerability records",
            )

            # ----------------------------------------------------------
            # Notifications
            # ----------------------------------------------------------
            ew.log(smi.LogLevel.INFO, "Collecting notifications")
            page = 1
            page_size = 50

            while True:
                resp = api.get(
                    "/api/v2/notifications",
                    params={"pageSize": page_size, "pageNumber": page},
                )
                notes = resp.get("content", [])
                for n in notes:
                    ew.write_event(
                        smi.Event(
                            to_json(n),
                            sourcetype="dragos:notifications",
                        )
                    )

                if len(notes) < page_size:
                    break
                page += 1

            ew.log(smi.LogLevel.INFO, "Notification collection completed")

        ew.log(smi.LogLevel.INFO, "Dragos input completed successfully")


if __name__ == "__main__":
    sys.exit(DragosInput().run(sys.argv))
