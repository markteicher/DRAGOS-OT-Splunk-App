#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: /bin/dragos_input.py
#
# Dragos OT Security for Splunk App
#
# Supported endpoints:
#   - Assets (inventory, paged):
#       GET /api/v2/assets?pageSize=<n>&pageNumber=<n>
#
#   - Notifications (paged):
#       GET /api/v2/notifications?pageSize=<n>&pageNumber=<n>
#
#   - Indicators / IOCs (paged + incremental):
#       GET /api/v1/indicators?page_size=<n>&page=<n>&updated_after=<iso8601>
#
#   - Vulnerabilities (best-effort; response varies by deployment):
#       GET /api/v1/vulnerabilities
#
# Collection rules:
# - One Splunk event per record (no aggregation)
# - Preserve raw JSON returned by Dragos
#
# Authentication:
# - This script supports a configurable header-based API token.
#   Defaults:
#     auth_header_name   = Authorization
#     auth_header_prefix = Bearer
#
# Proxy:
# - Optional proxy_url, proxy_user, proxy_pass
#
# TLS:
# - verify_ssl boolean
# - Optional CA bundle path via ca_bundle (must exist on the host)
#
# NOTE: This script is designed to be used by a SINGLE Splunk App (no TA).

import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import splunklib.modularinput as smi


# -----------------------------
# Helpers
# -----------------------------

def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso_to_dt(value: str) -> Optional[datetime]:
    """
    Parse common ISO-8601 formats including a trailing 'Z'.
    Returns UTC datetime or None.
    """
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    try:
        if s.endswith("Z"):
            # Normalize Zulu time
            s = s[:-1] + "+00:00"
        # datetime.fromisoformat handles offsets
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def _dt_to_unix(dt: datetime) -> int:
    return int(dt.timestamp())

def _unix_to_iso(unix_ts: int) -> str:
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()

def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


# -----------------------------
# Checkpointing (Splunk-managed directory)
# -----------------------------

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
        json.dump(data, fh, ensure_ascii=False)
    os.replace(tmp, path)


# -----------------------------
# HTTP Client
# -----------------------------

@dataclass
class DragosAuth:
    header_name: str = "Authorization"
    header_prefix: str = "Bearer"

    def build(self, token: str) -> Dict[str, str]:
        token = (token or "").strip()
        if not token:
            return {}
        if self.header_prefix:
            return {self.header_name: f"{self.header_prefix} {token}"}
        return {self.header_name: token}


class DragosAPI:
    def __init__(
        self,
        base_url: str,
        api_token: str,
        log,
        auth_header_name: str = "Authorization",
        auth_header_prefix: str = "Bearer",
        verify_ssl: bool = True,
        ca_bundle: Optional[str] = None,
        timeout: int = 60,
        proxy_url: Optional[str] = None,
        proxy_user: Optional[str] = None,
        proxy_pass: Optional[str] = None,
        max_retries: int = 5,
        backoff_factor: float = 1.0,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.timeout = timeout
        self.log = log

        self.auth = DragosAuth(auth_header_name, auth_header_prefix)
        self.api_token = api_token or ""

        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        self.session.headers.update(self.auth.build(self.api_token))

        # TLS
        self.session.verify = verify_ssl if ca_bundle is None else ca_bundle

        # Retry policy
        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            status=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

        # Proxy
        if proxy_url:
            proxy = proxy_url.strip()
            if proxy_user and proxy_pass:
                proxy = proxy.replace("://", f"://{proxy_user}:{proxy_pass}@", 1)
            self.session.proxies = {"http": proxy, "https": proxy}

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, params=params or {}, timeout=self.timeout)

        # If Dragos returns non-2xx, raise with context
        if resp.status_code >= 400:
            body = resp.text[:2000] if resp.text else ""
            raise RuntimeError(f"HTTP {resp.status_code} GET {path} :: {body}")

        # Some deployments may return empty bodies on success
        if not resp.content:
            return {}

        # Parse JSON
        try:
            return resp.json()
        except Exception:
            # Keep the raw text if JSON parsing fails
            return {"_raw": resp.text}


# -----------------------------
# Collector implementations
# -----------------------------

def emit_events(
    ew,
    records: Iterable[Any],
    sourcetype: str,
    source: str,
    index: Optional[str] = None,
) -> int:
    count = 0
    for rec in records:
        evt = smi.Event(
            data=_json_dumps(rec),
            sourcetype=sourcetype,
            source=source,
            index=index if index else None,
        )
        ew.write_event(evt)
        count += 1
    return count


def collect_assets(api: DragosAPI, ew, index: Optional[str], page_size: int, log) -> int:
    """
    GET /api/v2/assets?pageSize=<n>&pageNumber=<n>
    Expected response:
      { "content": [ ... ], "meta": { "pageNumber": 1, "pageSize": 50, "totalItems": 11966, ... } }
    """
    total_written = 0
    page = 1

    while True:
        payload = api.get("/api/v2/assets", params={"pageSize": page_size, "pageNumber": page})
        content = payload.get("content", []) if isinstance(payload, dict) else []
        meta = payload.get("meta", {}) if isinstance(payload, dict) else {}
        written = emit_events(
            ew,
            content,
            sourcetype="dragos:assets",
            source="dragos:/api/v2/assets",
            index=index,
        )
        total_written += written

        total_items = _safe_int(meta.get("totalItems"), 0)
        page_number = _safe_int(meta.get("pageNumber"), page)
        this_page_size = _safe_int(meta.get("pageSize"), page_size)

        log(smi.LogLevel.INFO, f"Assets page {page_number} wrote={written} total_written={total_written} totalItems={total_items}")

        if written == 0:
            break

        # Stop when we have written all items (best effort)
        if total_items > 0 and total_written >= total_items:
            break

        # Safety: if meta doesn't advance or is missing, still advance page but cap via empty page
        page += 1

    return total_written


def collect_notifications(api: DragosAPI, ew, index: Optional[str], page_size: int, log, ckpt: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """
    GET /api/v2/notifications?pageSize=<n>&pageNumber=<n>
    Expected response:
      { "meta": {...}, "content": [ ... ] }
    Checkpoint:
      - notifications_last_ts (unix)
    """
    total_written = 0
    page = 1
    last_ts = _safe_int(ckpt.get("notifications_last_ts", 0), 0)

    max_seen_ts = last_ts

    while True:
        payload = api.get("/api/v2/notifications", params={"pageSize": page_size, "pageNumber": page})
        content = payload.get("content", []) if isinstance(payload, dict) else []
        meta = payload.get("meta", {}) if isinstance(payload, dict) else {}

        # best-effort incremental filtering client-side (if timestamps exist)
        filtered: List[Dict[str, Any]] = []
        for item in content:
            if not isinstance(item, dict):
                filtered.append(item)
                continue

            # choose first available timestamp field commonly observed
            ts_dt = (
                _iso_to_dt(item.get("updatedAt", "")) or
                _iso_to_dt(item.get("createdAt", "")) or
                _iso_to_dt(item.get("lastSeenAt", "")) or
                _iso_to_dt(item.get("firstSeenAt", ""))
            )
            if ts_dt:
                ts_unix = _dt_to_unix(ts_dt)
                if ts_unix >= last_ts:
                    filtered.append(item)
                if ts_unix > max_seen_ts:
                    max_seen_ts = ts_unix
            else:
                # if no timestamp is present, do not drop
                filtered.append(item)

        written = emit_events(
            ew,
            filtered,
            sourcetype="dragos:notifications",
            source="dragos:/api/v2/notifications",
            index=index,
        )
        total_written += written

        total_items = _safe_int(meta.get("totalItems"), 0)
        page_number = _safe_int(meta.get("pageNumber"), page)
        log(smi.LogLevel.INFO, f"Notifications page {page_number} wrote={written} total_written={total_written} totalItems={total_items} ckpt={last_ts}")

        if len(content) == 0:
            break

        if total_items > 0 and (page_number * page_size) >= total_items:
            break

        page += 1

    # update checkpoint to latest timestamp seen (or now if we ingested anything but saw no timestamps)
    if total_written > 0:
        if max_seen_ts == last_ts:
            max_seen_ts = _dt_to_unix(_now_utc())

    ckpt["notifications_last_ts"] = max_seen_ts
    return total_written, ckpt


def collect_iocs(api: DragosAPI, ew, index: Optional[str], page_size: int, log, ckpt: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """
    GET /api/v1/indicators?page_size=<n>&page=<n>&updated_after=<iso8601>
    Expected response (common):
      { "indicators": [ ... ], "total_pages": <n>, ... }
    Checkpoint:
      - iocs_last_ts (unix)
    """
    total_written = 0
    last_ts = _safe_int(ckpt.get("iocs_last_ts", 0), 0)
    updated_after = _unix_to_iso(last_ts)

    page = 1
    total_pages = 1
    max_seen_ts = last_ts

    while page <= total_pages:
        payload = api.get(
            "/api/v1/indicators",
            params={
                "page_size": page_size,
                "page": page,
                "updated_after": updated_after,
            },
        )

        indicators = []
        if isinstance(payload, dict):
            indicators = payload.get("indicators", []) or payload.get("items", []) or []
            total_pages = _safe_int(payload.get("total_pages", total_pages), total_pages)
        elif isinstance(payload, list):
            indicators = payload
            total_pages = 1

        # track max timestamp if present
        for item in indicators:
            if isinstance(item, dict):
                dt = _iso_to_dt(item.get("updated_at", "")) or _iso_to_dt(item.get("updatedAt", "")) or _iso_to_dt(item.get("last_seen", "")) or _iso_to_dt(item.get("lastSeen", ""))
                if dt:
                    ts = _dt_to_unix(dt)
                    if ts > max_seen_ts:
                        max_seen_ts = ts

        written = emit_events(
            ew,
            indicators,
            sourcetype="dragos:indicators",
            source="dragos:/api/v1/indicators",
            index=index,
        )
        total_written += written
        log(smi.LogLevel.INFO, f"IOCs page {page}/{total_pages} wrote={written} total_written={total_written} updated_after={updated_after}")

        if written == 0 and page == 1:
            break

        page += 1

    if total_written > 0:
        if max_seen_ts == last_ts:
            max_seen_ts = _dt_to_unix(_now_utc())
        ckpt["iocs_last_ts"] = max_seen_ts

    return total_written, ckpt


def collect_vulnerabilities(api: DragosAPI, ew, index: Optional[str], log, ckpt: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """
    GET /api/v1/vulnerabilities
    Response observed in the wild:
      - list of vulnerability observation objects
      - or dict wrappers
    Checkpoint:
      - vulnerabilities_last_ts (unix) best-effort (uses lastObservedTime/updatedAt/etc if present)
    """
    last_ts = _safe_int(ckpt.get("vulnerabilities_last_ts", 0), 0)
    max_seen_ts = last_ts

    payload = api.get("/api/v1/vulnerabilities")

    records: List[Any] = []
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        # tolerate different wrappers
        records = payload.get("items", []) or payload.get("content", []) or payload.get("vulnerabilities", []) or []
        # if it looks like a single record
        if not records and payload:
            records = [payload]

    # client-side incremental filtering (best-effort) + timestamp tracking
    filtered: List[Any] = []
    for rec in records:
        if not isinstance(rec, dict):
            filtered.append(rec)
            continue

        # Some responses embed the useful object under "value"
        obj = rec.get("value", rec)

        dt = (
            _iso_to_dt(obj.get("lastObservedTime", "")) or
            _iso_to_dt(obj.get("firstObservedTime", "")) or
            _iso_to_dt(obj.get("updatedAt", "")) or
            _iso_to_dt(obj.get("updated_at", "")) or
            _iso_to_dt(obj.get("createdAt", "")) or
            _iso_to_dt(obj.get("created_at", ""))
        )
        if dt:
            ts = _dt_to_unix(dt)
            if ts >= last_ts:
                filtered.append(rec)
            if ts > max_seen_ts:
                max_seen_ts = ts
        else:
            filtered.append(rec)

    written = emit_events(
        ew,
        filtered,
        sourcetype="dragos:vulnerabilities",
        source="dragos:/api/v1/vulnerabilities",
        index=index,
    )

    log(smi.LogLevel.INFO, f"Vulnerabilities wrote={written} total_seen={len(records)} filtered={len(filtered)} ckpt={last_ts}")

    if written > 0:
        if max_seen_ts == last_ts:
            max_seen_ts = _dt_to_unix(_now_utc())
        ckpt["vulnerabilities_last_ts"] = max_seen_ts

    return written, ckpt


# -----------------------------
# Modular Input
# -----------------------------

class DragosInput(smi.Script):
    def get_scheme(self):
        scheme = smi.Scheme("Dragos OT Security Input")
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True

        scheme.add_argument(smi.Argument("name", "Name", smi.Argument.data_type_string, True))

        # Connection
        scheme.add_argument(smi.Argument("dragos_url", "Dragos Base URL", smi.Argument.data_type_string, True))
        scheme.add_argument(smi.Argument("api_token", "API Token", smi.Argument.data_type_string, True, encrypted=True))

        # Auth header customization (rarely needed, but avoids hardcoding assumptions)
        scheme.add_argument(smi.Argument("auth_header_name", "Auth Header Name", smi.Argument.data_type_string, False))
        scheme.add_argument(smi.Argument("auth_header_prefix", "Auth Header Prefix", smi.Argument.data_type_string, False))

        # TLS / HTTP behavior
        scheme.add_argument(smi.Argument("verify_ssl", "Verify SSL", smi.Argument.data_type_boolean, False))
        scheme.add_argument(smi.Argument("ca_bundle", "CA Bundle Path", smi.Argument.data_type_string, False))
        scheme.add_argument(smi.Argument("timeout", "Timeout Seconds", smi.Argument.data_type_number, False))

        # Proxy
        scheme.add_argument(smi.Argument("proxy_url", "Proxy URL", smi.Argument.data_type_string, False))
        scheme.add_argument(smi.Argument("proxy_user", "Proxy Username", smi.Argument.data_type_string, False))
        scheme.add_argument(smi.Argument("proxy_pass", "Proxy Password", smi.Argument.data_type_string, False, encrypted=True))

        # Collection controls
        scheme.add_argument(smi.Argument("target_index", "Target Index", smi.Argument.data_type_string, False))
        scheme.add_argument(smi.Argument("page_size", "Page Size", smi.Argument.data_type_number, False))

        scheme.add_argument(smi.Argument("collect_assets", "Collect Assets", smi.Argument.data_type_boolean, False))
        scheme.add_argument(smi.Argument("collect_notifications", "Collect Notifications", smi.Argument.data_type_boolean, False))
        scheme.add_argument(smi.Argument("collect_iocs", "Collect IOCs", smi.Argument.data_type_boolean, False))
        scheme.add_argument(smi.Argument("collect_vulnerabilities", "Collect Vulnerabilities", smi.Argument.data_type_boolean, False))

        return scheme

    def validate_input(self, definition):
        p = definition.parameters

        base_url = (p.get("dragos_url") or "").strip()
        token = (p.get("api_token") or "").strip()
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            raise ValueError("dragos_url must begin with http:// or https://")
        if not token:
            raise ValueError("api_token is required")

        # Validate CA bundle if provided
        ca_bundle = (p.get("ca_bundle") or "").strip() or None
        if ca_bundle and not os.path.exists(ca_bundle):
            raise ValueError(f"ca_bundle does not exist: {ca_bundle}")

        # Connectivity check: a lightweight GET to one endpoint.
        # Prefer /api/v1/indicators (read-only) with minimal params.
        api = DragosAPI(
            base_url=base_url,
            api_token=token,
            log=lambda *_: None,
            auth_header_name=(p.get("auth_header_name") or "Authorization"),
            auth_header_prefix=(p.get("auth_header_prefix") or "Bearer"),
            verify_ssl=bool(p.get("verify_ssl", True)),
            ca_bundle=ca_bundle,
            timeout=_safe_int(p.get("timeout", 60), 60),
            proxy_url=p.get("proxy_url"),
            proxy_user=p.get("proxy_user"),
            proxy_pass=p.get("proxy_pass"),
        )
        _ = api.get("/api/v1/indicators", params={"page_size": 1, "page": 1, "updated_after": _unix_to_iso(0)})

    def stream_events(self, inputs, ew):
        ew.log(smi.LogLevel.INFO, "Dragos input starting")

        for stanza, cfg in inputs.inputs.items():
            params = cfg.get("params", {})
            checkpoint_dir = cfg.get("checkpoint_dir", "")
            ckpt_path = os.path.join(checkpoint_dir, f"{stanza}.json")
            ckpt = load_checkpoint(ckpt_path)

            base_url = (params.get("dragos_url") or "").strip()
            token = (params.get("api_token") or "").strip()

            auth_header_name = (params.get("auth_header_name") or "Authorization").strip()
            auth_header_prefix = (params.get("auth_header_prefix") or "Bearer").strip()

            verify_ssl = bool(params.get("verify_ssl", True))
            ca_bundle = (params.get("ca_bundle") or "").strip() or None
            timeout = _safe_int(params.get("timeout", 60), 60)

            proxy_url = params.get("proxy_url")
            proxy_user = params.get("proxy_user")
            proxy_pass = params.get("proxy_pass")

            index = (params.get("target_index") or "").strip() or None
            page_size = _safe_int(params.get("page_size", 100), 100)
            if page_size <= 0:
                page_size = 100

            collect_assets_flag = bool(params.get("collect_assets", True))
            collect_notifications_flag = bool(params.get("collect_notifications", True))
            collect_iocs_flag = bool(params.get("collect_iocs", True))
            collect_vulns_flag = bool(params.get("collect_vulnerabilities", True))

            api = DragosAPI(
                base_url=base_url,
                api_token=token,
                log=ew.log,
                auth_header_name=auth_header_name,
                auth_header_prefix=auth_header_prefix,
                verify_ssl=verify_ssl,
                ca_bundle=ca_bundle,
                timeout=timeout,
                proxy_url=proxy_url,
                proxy_user=proxy_user,
                proxy_pass=proxy_pass,
            )

            # Collector execution (explicit, logged, checkpointed)
            if collect_assets_flag:
                start = time.time()
                ew.log(smi.LogLevel.INFO, "Collecting: assets")
                written = collect_assets(api, ew, index, page_size, ew.log)
                ew.log(smi.LogLevel.INFO, f"Completed: assets written={written} duration={round(time.time()-start, 2)}s")

            if collect_notifications_flag:
                start = time.time()
                ew.log(smi.LogLevel.INFO, "Collecting: notifications")
                written, ckpt = collect_notifications(api, ew, index, page_size, ew.log, ckpt)
                save_checkpoint(ckpt_path, ckpt)
                ew.log(smi.LogLevel.INFO, f"Completed: notifications written={written} duration={round(time.time()-start, 2)}s ckpt={ckpt.get('notifications_last_ts', 0)}")

            if collect_iocs_flag:
                start = time.time()
                ew.log(smi.LogLevel.INFO, "Collecting: iocs")
                written, ckpt = collect_iocs(api, ew, index, page_size, ew.log, ckpt)
                save_checkpoint(ckpt_path, ckpt)
                ew.log(smi.LogLevel.INFO, f"Completed: iocs written={written} duration={round(time.time()-start, 2)}s ckpt={ckpt.get('iocs_last_ts', 0)}")

            if collect_vulns_flag:
                start = time.time()
                ew.log(smi.LogLevel.INFO, "Collecting: vulnerabilities")
                written, ckpt = collect_vulnerabilities(api, ew, index, ew.log, ckpt)
                save_checkpoint(ckpt_path, ckpt)
                ew.log(smi.LogLevel.INFO, f"Completed: vulnerabilities written={written} duration={round(time.time()-start, 2)}s ckpt={ckpt.get('vulnerabilities_last_ts', 0)}")

        ew.log(smi.LogLevel.INFO, "Dragos input completed successfully")


if __name__ == "__main__":
    sys.exit(DragosInput().run(sys.argv))
