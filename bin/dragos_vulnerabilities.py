#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
dragos_vulnerabilities.py

Dragos OT Security for Splunk App
Vulnerability Intelligence Ingestion

Endpoint:
  GET /api/v1/vulnerabilities

========================================================================
FIELDS
========================================================================

value.id

value.report.type
value.report.id
value.report.expandedState
value.report.expansionTime

value.report.expanded.id
value.report.expanded.score.base
value.report.expanded.score.dragos
value.report.expanded.title
value.report.expanded.description
value.report.expanded.enumeration
value.report.expanded.severity
value.report.expanded.publishedTime
value.report.expanded.state
value.report.expanded.summaryHtml
value.report.expanded.mitigationsHtml[]
value.report.expanded.playbooksHtml[]

value.report.expanded.links[].url
value.report.expanded.links[].label

value.source.name
value.source.product
value.source.type
value.source.vendor
value.source.version

value.ports[].number
value.ports[].protocols[]
value.ports[].status

value.relatedReports[].type
value.relatedReports[].id
value.relatedReports[].expandedState

value.tags[].id
value.tags[].label

value.reasons[].type
value.reasons[].criteria[]
value.reasons[].host

value.confidence
value.risk
value.priority
value.disposition
value.firstObservedTime
value.lastObservedTime

value.asset.type
value.asset.id
value.asset.expandedState
value.asset.expansionTime

value.asset.expanded.id
value.asset.expanded.name
value.asset.expanded.type
value.asset.expanded.class

value.asset.expanded.zone.type
value.asset.expanded.zone.id
value.asset.expanded.zone.expandedState

value.asset.expanded.tags[]

value.asset.expanded.addresses[].type
value.asset.expanded.addresses[].id
value.asset.expanded.addresses[].expandedState

value.asset.expanded.connectedRootDevice

value.asset.expanded.notificationCounts.type
value.asset.expanded.notificationCounts.id
value.asset.expanded.notificationCounts.expandedState

value.asset.expanded.vulnerabilityCounts.type
value.asset.expanded.vulnerabilityCounts.id
value.asset.expanded.vulnerabilityCounts.expandedState

value.asset.expanded.firstObservedTime
value.asset.expanded.lastObservedTime
value.asset.expanded.ot

value.asset.expanded.baselines[]

value.asset.expanded.hardware.firmware
value.asset.expanded.hardware.model
value.asset.expanded.hardware.vendor

value.asset.expanded.monitored
value.asset.expanded.vlan

value.asset.expanded.labels.zone_name
value.asset.expanded.labels.ObservedBy[]
value.asset.expanded.labels.Monitored-OT
value.asset.expanded.labels.Monitored-MAC
value.asset.expanded.labels.Monitored-OTPeer
value.asset.expanded.labels.Monitored-MACPeer
value.asset.expanded.labels.hardware.fidelity

===============================================================
"""

from datetime import datetime
import pytz

from dragoslib import platform_input_utils as dragos_platform_input_utils


# ----------------------------------------------------------------------
# API request
# ----------------------------------------------------------------------
def submit_request_to_platform_api(session, page_number, preferred_batch_size, **kwargs):
    """
    Fetch vulnerabilities updated after checkpoint
    """

    params = {
        "page": page_number,
        "page_size": preferred_batch_size,
        "updated_after": datetime.fromtimestamp(
            kwargs["unix_timestamp_checkpoint"], pytz.utc
        ).isoformat(),
    }

    return session.get("/api/v1/vulnerabilities", params=params)


# ----------------------------------------------------------------------
# Event writer
# ----------------------------------------------------------------------
def write_splunk_item(dic_rest, helper, ew, dragos_input_utils):
    """
    Write each vulnerability object as a single Splunk event
    """

    records = dic_rest if isinstance(dic_rest, list) else dic_rest.get("items", [])

    helper.logger.info(f"Writing {len(records)} vulnerability events to Splunk")

    for record in records:
        obj_data = dragos_input_utils.format_individual_data_item_for_splunk(record)
        event = dragos_input_utils.new_event_for_slunk(helper, obj_data)
        ew.write_event(event)

    # Paging metadata is not explicitly exposed
    return dic_rest.get("total_pages", 1)


# ----------------------------------------------------------------------
# Validation
# ----------------------------------------------------------------------
def validate_input(helper, definition):
    """
    Minimal validation only
    """

    dragos_platform_input_utils.PlatformInputUtils().validate_input_parameters(
        helper, definition.parameters
    )


# ----------------------------------------------------------------------
# Collection orchestration
# ----------------------------------------------------------------------
def collect_events(helper, ew):
    """
    Main collection loop with checkpointing
    """

    input_utils = dragos_platform_input_utils.PlatformInputUtils()
    session = input_utils.collect_events_initialization(helper)

    unix_timestamp_now = input_utils.datetime_to_unix_timestamp(datetime.now(pytz.utc))

    token_name = f"{helper.get_input_type()}-{list(helper.get_input_stanza().keys())[0]}-timestamp"
    unix_timestamp_checkpoint = helper.get_check_point(token_name) or 0

    helper.logger.info(
        f"Using vulnerability checkpoint {unix_timestamp_checkpoint}"
    )

    api_context = {
        "unix_timestamp_checkpoint": unix_timestamp_checkpoint,
        "unix_timestamp_now": unix_timestamp_now,
    }

    input_utils.collect_events_from_api(
        helper,
        ew,
        submit_request_to_platform_api,
        write_splunk_item,
        session=session,
        api_context=api_context,
    )

    helper.logger.info(
        f"Saving vulnerability checkpoint {unix_timestamp_now}"
    )
    helper.save_check_point(token_name, unix_timestamp_now)
