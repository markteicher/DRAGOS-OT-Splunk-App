# dragos_client.py
#
# Shared Dragos API client for Dragos OT Security for Splunk
#
# This client is used by all modular inputs to retrieve data
# from the Dragos REST API.
#

import json
import logging
import time
from typing import Dict, Any, Optional

import requests

logger = logging.getLogger(__name__)


class DragosAPIClient:
    """
    Thin, reusable client for the Dragos REST API.

    Responsibilities:
        - Authentication handling
        - Request execution
        - Error handling
        - Pagination support (where applicable)
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 60,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "User-Agent": "Dragos-Splunk-App/1.0.0",
            }
        )

        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy,
            }

    # ------------------------------------------------------------------
    # Core request method
    # ------------------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"

        try:
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except requests.RequestException as exc:
            logger.error("Dragos API request failed: %s", exc)
            raise

        if resp.status_code >= 400:
            logger.error(
                "Dragos API error %s: %s",
                resp.status_code,
                resp.text,
            )
            resp.raise_for_status()

        try:
            return resp.json()
        except ValueError:
            logger.error("Invalid JSON response from Dragos API")
            raise

    # ------------------------------------------------------------------
    # Pagination helper
    # ------------------------------------------------------------------
    def get_paginated(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        page_field: str = "items",
        next_field: str = "next",
    ):
        """
        Generator for paginated endpoints.

        Assumes Dragos-style pagination with a 'next' link or cursor.
        """
        current_params = params or {}

        while True:
            data = self._request("GET", path, current_params)

            items = data.get(page_field, [])
            for item in items:
                yield item

            next_token = data.get(next_field)
            if not next_token:
                break

            current_params["cursor"] = next_token
            time.sleep(0.2)  # light throttling

    # ------------------------------------------------------------------
    # Endpoint wrappers (explicit, readable)
    # ------------------------------------------------------------------
    def get_alerts(self):
        return self.get_paginated("/api/v1/alerts")

    def get_assets(self):
        return self.get_paginated("/api/v1/assets")

    def get_threat_intel(self):
        return self.get_paginated("/api/v1/threat-intel")

    def get_network_telemetry(self):
        return self.get_paginated("/api/v1/network-telemetry")
