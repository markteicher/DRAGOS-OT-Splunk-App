#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# File: bin/dragos_validation.py
# -------------------------------------------------------------------------
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
#     * Unix-style informational logging via Splunk validation handler
#     * no stdout printing
#
# - Purpose:
#     * Input validation for Splunk modular input configuration
#     * Authentication and basic API reachability checks only
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


def validate_input(definition):
    """
    Splunk calls this method to validate the modular input configuration
    before enabling the input.
    """
    params = definition.parameters

    dragos_url = params.get("dragos_url")
    api_token = params.get("api_token")

    verify_ssl = params.get("verify_ssl", True)
    timeout = int(params.get("timeout", 60))

    proxy_url = params.get("proxy_url")
    proxy_user = params.get("proxy_user")
    proxy_pass = params.get("proxy_pass")

    if not dragos_url:
        raise ValueError("Missing required parameter: dragos_url")
    if not api_token:
        raise ValueError("Missing required parameter: api_token")

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
            proxy = proxy_url.replace("://", f"://{proxy_user}:{proxy_pass}@", 1)
        session.proxies = {"http": proxy, "https": proxy}

    # Basic API validation
    version_url = f"{dragos_url.rstrip('/')}/api/v1/version"
    resp = session.get(version_url, timeout=timeout)
    resp.raise_for_status()
