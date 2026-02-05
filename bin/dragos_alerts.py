#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
dragos_alerts.py

Dragos OT Security for Splunk App
Alert / Notification Ingestion

Endpoint:
  GET /notifications/api/v2/notification

========================================================================
FIELD INVENTORY
========================================================================

id
type
severity
summary
name
createdAt

dragos_source

assets[].id
assets[].directionalities[]

assets[].addresses[].type
assets[].addresses[].value

source_ips[]
source_macs[]
source_hostnames[]
source_domains[]

destination_ips[]
destination_macs[]
destination_hostnames[]
destination_domains[]

notifications.apiVersion (if present)
notifications.schemaVersion (if present)

relatedEntities[].type
relatedEntities[].id
relatedEntities[].expandedState

confidence
risk
priority
disposition

firstObservedTime
lastObservedTime

tags[]

source.name
source.product
source.vendor
source.type
source.version

========================================================================
"""

from datetime import datetime
import pytz
import iso8601
from collections import OrderedDict

from dragoslib import platform_input_utils as dragos_platform_input_utils
from dragoslib import app_config as dragos_app_config


UNIX_EPOCH_ISO_8601 = "1970-01-01T00:00:00Z"
TIMESTAMP_BOOKMARK_NAME = "timestamp"


# ----------------------------------------------------------------------
# API request
# ----------------------------------------------------------------------
def submit_request_to_platform_api(session, page_number, preferred_batch_size, **kwargs):

    earliest = datetime.fromtimestamp(
        kwargs["unix_timestamp_checkpoint"] - kwargs["backward_shift_seconds"],
        pytz.utc,
    ).isoformat()

    now = datetime.fromtimestamp(
        kwargs["unix_timestamp_now"] - kwargs["backward_shift_seconds"],
        pytz.utc,
    ).isoformat()

    params = {
        "pageNumber": page_number,
        "pageSize": preferred_batch_size,
        "sorts": "createdAt:a",
        "filter": f"type!='Baseline';createdAt=gt='{earliest}';createdAt=le='{now}';type!='System'",
    }

    return session.get("/notifications/api/v2/notification", params=params)


# ----------------------------------------------------------------------
# Event writer
# ----------------------------------------------------------------------
def write_splunk_item(dic_rest, helper, ew, dragos_input_utils):

    helper.logger.info(
        f"Writing {len(dic_rest['content'])} alert events to Splunk"
    )

    for item in dic_rest["content"]:

        # Preserve original structure; only minimal collision avoidance
        if "source" in item:
            item["dragos_source"] = item.pop("source")

        # Ensure valid ISO8601 timestamp
        if "createdAt" not in item:
            item["createdAt"] = datetime.now(pytz.utc).isoformat()
        else:
            try:
                iso8601.parse_date(item["createdAt"])
            except iso8601.ParseError:
                item["createdAt"] = datetime.now(pytz.utc).isoformat()

        # Reorder to prioritize createdAt (Splunk timestamp performance)
        top_fields = ["createdAt", "type", "severity", "summary", "name"]
        ordered = OrderedDict()
        for f in top_fields:
            if f in item:
                ordered[f] = item.pop(f)

        ordered.update(item)

        obj_data = dragos_input_utils.format_individual_data_item_for_splunk(ordered)
        event = dragos_input_utils.new_event_for_slunk(helper, obj_data)
        ew.write_event(event)

    # Update checkpoint to last event minus one second
    if dic_rest["content"]:
        last_ts = iso8601.parse_date(dic_rest["content"][-1]["createdAt"])
        checkpoint = (
            dragos_platform_input_utils.PlatformInputUtils()
            .datetime_to_unix_timestamp(last_ts)
            - 1
        )
        helper.save_check_point(
            get_bookmark_name(helper, TIMESTAMP_BOOKMARK_NAME),
            checkpoint,
        )

    return dic_rest["totalPages"]


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def get_bookmark_name(helper, name):
    return f"{helper.get_input_type()}-{list(helper.get_input_stanza().keys())[0]}-{name}"


# ----------------------------------------------------------------------
# Validation
# ----------------------------------------------------------------------
def validate_input(helper, definition):

    dragos_platform_input_utils.PlatformInputUtils().validate_input_parameters(
        helper, definition.parameters
    )

    timestamp_bookmark = definition.parameters.get("timestamp_bookmark")
    if timestamp_bookmark:
        try:
            iso8601.parse_date(timestamp_bookmark)
        except iso8601.ParseError:
            raise ValueError(
                f"Invalid ISO8601 timestamp_bookmark: {timestamp_bookmark}"
            )


# ----------------------------------------------------------------------
# Collection orchestration
# ----------------------------------------------------------------------
def collect_events(helper, ew):

    input_utils = dragos_platform_input_utils.PlatformInputUtils()
    session = input_utils.collect_events_initialization(helper)

    unix_timestamp_now = input_utils.datetime_to_unix_timestamp(datetime.now(pytz.utc))

    token_name = get_bookmark_name(helper, TIMESTAMP_BOOKMARK_NAME)
    unix_timestamp_checkpoint = helper.get_check_point(token_name)

    if not unix_timestamp_checkpoint:
        unix_timestamp_checkpoint = input_utils.datetime_to_unix_timestamp(
            iso8601.parse_date(helper.get_arg("timestamp_bookmark"))
        )

    api_context = {
        "unix_timestamp_checkpoint": unix_timestamp_checkpoint,
        "unix_timestamp_now": unix_timestamp_now,
        "backward_shift_seconds": int(
            dragos_app_config.AppConfig()
            .dragos_worldview_notification_query_backward_shift_seconds()
        ),
    }

    input_utils.collect_events_from_api(
        helper,
        ew,
        submit_request_to_platform_api,
        write_splunk_item,
        session=session,
        api_context=api_context,
    )

    helper.save_check_point(token_name, unix_timestamp_now)
