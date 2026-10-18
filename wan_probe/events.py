"""Structured event log: one JSON line per state change, on stdout.

The platform's log shipper (Alloy) carries every pod's stdout to
VictoriaLogs, so these lines are the service's history without a store of
its own: WAN added or removed, rule created or deleted, ISP changed,
steering flipped, reconcile failed. Fields are flat and stable so they can
be queried by name.
"""
import json
import logging
import time

log = logging.getLogger("wan-probe.event")


def emit(event, **fields):
    record = {"event": event, "ts": round(time.time(), 3)}
    record.update({k: v for k, v in fields.items() if v is not None})
    log.info(json.dumps(record, sort_keys=True, default=str))
    return record
