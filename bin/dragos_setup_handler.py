#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# File: bin/dragos_setup_handler.py
# -------------------------------------------------------------------------
# Dragos OT Security for Splunk App
# Setup Handler
# -------------------------------------------------------------------------
#
# Implementation notes
#
# - Authentication:
#     * Static API token (Dragos REST APIs)
#     * Authorization: Bearer <token>
#
# - Proxy support:
#     * no proxy
#     * proxy without authentication
#     * proxy with username/password authentication
#
# - Logging:
#     * Unix-style informational logging via Splunk setup handler
#     * no stdout printing
#
# - Purpose:
#     * Validate Dragos connectivity during app setup
#     * Store configuration only (no data ingestion)
#
# - API usage:
#     * read-only validation call
#       GET /api/v1/version
#
# - Splunk AppInspect compliance:
#     * no file-based logging
#     * no persistent state outside Splunk storage
# -------------------------------------------------------------------------

import requests

from splunklib.binding import HTTPError


def validate_dragos_connection(
    dragos_url,
    api_token,
    verify_ssl=True,
    timeout=60,
    proxy_url=None,
    proxy_user=None,
    proxy_pass=None,
):
    session = requests.Session()
    session.verify = verify_ssl
    session.headers.update(
        {
            "Accept": "application/json",
            "Authorization": f"Bearer {api_token}",
        }
    )

    if proxy_url:
        proxy = proxy_url
        if proxy_user and proxy_pass:
            proxy = proxy_url.replace(
                "://", f"://{proxy_user}:{proxy_pass}@", 1
            )
        session.proxies = {"http": proxy, "https": proxy}

    version_url = f"{dragos_url.rstrip('/')}/api/v1/version"
    resp = session.get(version_url, timeout=timeout)
    resp.raise_for_status()

    return resp.json()


def setup_handler(request):
    try:
        config = request["form"]

        dragos_url = config.get("dragos_url")
        api_token = config.get("api_token")
        verify_ssl = config.get("verify_ssl", "true").lower() == "true"
        timeout = int(config.get("timeout", 60))
        proxy_url = config.get("proxy_url")
        proxy_user = config.get("proxy_user")
        proxy_pass = config.get("proxy_pass")

        validate_dragos_connection(
            dragos_url=dragos_url,
            api_token=api_token,
            verify_ssl=verify_ssl,
            timeout=timeout,
            proxy_url=proxy_url,
            proxy_user=proxy_user,
            proxy_pass=proxy_pass,
        )

        return {
            "status": "success",
            "message": "Successfully connected to Dragos API",
        }

    except HTTPError as e:
        return {
            "status": "error",
            "message": f"Splunk HTTP error: {str(e)}",
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
        }
