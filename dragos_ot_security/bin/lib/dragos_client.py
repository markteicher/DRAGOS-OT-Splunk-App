# bin/lib/dragos_client.py

"""
Dragos API Client
=================

Shared HTTP client for the Dragos Platform API.

Used by:
    - dragos_alerts.py
    - dragos_assets.py
    - dragos_threat_intel.py
    - dragos_network.py

Responsibilities:
    - Authentication
    - Pagination
    - Error handling
    - Rate-safe requests
"""

import time
import requests


class DragosAPIError(Exception):
    """Generic Dragos API error."""
    pass


class DragosClient:
    """
    Thin client for Dragos REST API.
    """

    DEFAULT_TIMEOUT = 30
    DEFAULT_RETRIES = 3
    RETRY_BACKOFF = 2

    def __init__(
        self,
        base_url: str,
        api_key: str,
        proxy: str = None,
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
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Dragos-Splunk-App/1.0"
        })

        if proxy:
            self.session.proxies.update({
                "http": proxy,
                "https": proxy
            })

    # ------------------------------------------------------------------
    # Core request handler
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, params=None):
        url = f"{self.base_url}{path}"

        for attempt in range(1, self.DEFAULT_RETRIES + 1):
            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )

                if resp.status_code >= 400:
                    raise DragosAPIError(
                        f"HTTP {resp.status_code} – {resp.text}"
                    )

                return resp.json()

            except requests.RequestException as exc:
                if attempt == self.DEFAULT_RETRIES:
                    raise DragosAPIError(str(exc))

                time.sleep(self.RETRY_BACKOFF ** attempt)

    # ------------------------------------------------------------------
    # Pagination helper
    # ------------------------------------------------------------------

    def paged_get(self, path: str, params=None, page_key="items"):
        """
        Generator for paginated Dragos endpoints.
        """
        params = params or {}
        page = 1

        while True:
            params["page"] = page
            data = self._request("GET", path, params=params)

            items = data.get(page_key, [])
            if not items:
                break

            for item in items:
                yield item

            page += 1

    # ------------------------------------------------------------------
    # Endpoint helpers (used by inputs)
    # ------------------------------------------------------------------

    def get_alerts(self, **params):
        return self.paged_get("/api/v1/alerts", params=params)

    def get_assets(self, **params):
        return self.paged_get("/api/v1/assets", params=params)

    def get_threat_intel(self, **params):
        return self.paged_get("/api/v1/threat-intelligence", params=params)

    def get_network_activity(self, **params):
        return self.paged_get("/api/v1/network/activity", params=params)
