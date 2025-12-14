# dragos_client.py
"""
Shared API client for Dragos Platform REST API.

Used by:
    - dragos_alerts.py
    - dragos_assets.py
    - dragos_threat_intel.py
    - dragos_network_telemetry.py

Responsibilities:
    - Authentication
    - Proxy support
    - Pagination
    - Retry / backoff
    - Time-windowed collection
"""

import json
import time
import requests
from typing import Dict, List, Optional


class DragosAPIError(Exception):
    """Raised on Dragos API failures."""
    pass


class DragosClient:
    DEFAULT_TIMEOUT = 30
    MAX_RETRIES = 3
    BACKOFF_SECONDS = 2

    def __init__(
        self,
        base_url: str,
        api_key: str,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        if not base_url or not api_key:
            raise ValueError("base_url and api_key are required")

        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Dragos-Splunk-App/1.0"
        })

        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }

    # ------------------------------------------------------------------
    # LOW-LEVEL REQUEST
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        body: Optional[Dict] = None,
    ) -> Dict:
        url = f"{self.base_url}{endpoint}"

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=body,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            except requests.RequestException as exc:
                if attempt == self.MAX_RETRIES:
                    raise DragosAPIError(f"Connection error: {exc}")
                time.sleep(self.BACKOFF_SECONDS * attempt)
                continue

            if resp.status_code >= 400:
                if attempt == self.MAX_RETRIES:
                    raise DragosAPIError(
                        f"HTTP {resp.status_code}: {resp.text}"
                    )
                time.sleep(self.BACKOFF_SECONDS * attempt)
                continue

            try:
                return resp.json()
            except ValueError:
                raise DragosAPIError("Invalid JSON response from Dragos API")

        raise DragosAPIError("Unhandled request failure")

    # ------------------------------------------------------------------
    # PAGINATED COLLECTION
    # ------------------------------------------------------------------

    def collect_paginated(
        self,
        endpoint: str,
        params: Optional[Dict] = None,
        items_key: str = "items",
        page_param: str = "page",
        page_size_param: str = "page_size",
        page_size: int = 100,
        max_pages: Optional[int] = None,
    ) -> List[Dict]:
        """
        Generic pagination handler.

        Assumes:
            - Page-based pagination
            - JSON response with a list under `items_key`
        """
        results: List[Dict] = []
        page = 1

        while True:
            query = params.copy() if params else {}
            query[page_param] = page
            query[page_size_param] = page_size

            data = self._request("GET", endpoint, params=query)
            items = data.get(items_key, [])

            if not items:
                break

            results.extend(items)

            if max_pages and page >= max_pages:
                break

            page += 1

        return results

    # ------------------------------------------------------------------
    # TIME-WINDOWED COLLECTION
    # ------------------------------------------------------------------

    def collect_since(
        self,
        endpoint: str,
        since_ts: str,
        params: Optional[Dict] = None,
        time_param: str = "since",
        **kwargs
    ) -> List[Dict]:
        """
        Collect records newer than a timestamp.
        """
        query = params.copy() if params else {}
        query[time_param] = since_ts

        return self.collect_paginated(
            endpoint=endpoint,
            params=query,
            **kwargs
        )
