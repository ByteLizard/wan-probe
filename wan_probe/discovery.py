"""WAN discovery from the OPNsense exporter's series in VictoriaMetrics.

A WAN is a gateway whose name reads WANn with an OPNsense-style suffix
(WAN, WAN2_DHCP, WAN3_DHCP, WAN4_DHCP, WAN5_STATIC ...). The gateway
metric's `interface` label is the firewall's internal key (wan, opt7 ...),
which the rule API needs; the number comes from the name. Gateways that
do not fit the convention (WAN_EDGE, Proton_GW) are not WANs.

Presence is existence of the series, never gateway status: a down WAN is
still probed, that is the point. Removal needs sustained absence across
successful queries; a failed or empty query marks the firewall stale and
keeps the last known set.
"""
import json
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .dscp import DscpError, allocate

GATEWAY_RE = re.compile(r"^WAN([0-9]*)(?:_(?:DHCP|STATIC|PPPOE))?$", re.IGNORECASE)
INFO_QUERY = 'opnsense_gateways_info{enabled="true", protocol="inet", name=~"WAN[0-9]*(_DHCP|_STATIC|_PPPOE)?"}'
STATUS_QUERY = 'opnsense_gateways_status'


@dataclass(frozen=True)
class WanEntry:
    firewall: str
    gateway: str
    wan: str          # WAN1, WAN2 ... (WAN1 for the bare "WAN" gateway)
    number: int
    iface_key: str    # opnsense internal interface key (wan, opt12 ...)
    device: str       # ixl2 ...
    family: str       # inet / inet6
    dscp_name: str    # cs4
    tos: int          # 0x80

    @property
    def key(self):
        return (self.firewall, self.wan, self.family)


def wan_number(gateway_name):
    """WAN number for a gateway name, or None when it is not a WAN."""
    match = GATEWAY_RE.match(gateway_name or "")
    if not match:
        return None
    digits = match.group(1)
    return int(digits) if digits else 1


def query(vm_query_url, expr, timeout=15):
    url = vm_query_url + "?" + urllib.parse.urlencode({"query": expr})
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        payload = json.load(resp)
    if payload.get("status") != "success":
        raise RuntimeError(f"query failed: {payload}")
    return payload["data"]["result"]


def parse_entries(info_results, errors=None):
    """WanEntry list from opnsense_gateways_info result rows."""
    entries = []
    for row in info_results:
        metric = row.get("metric", {})
        number = wan_number(metric.get("name", ""))
        if number is None:
            continue
        try:
            dscp_name, tos = allocate(number)
        except DscpError as exc:
            if errors is not None:
                errors.append(str(exc))
            continue
        entries.append(WanEntry(
            firewall=metric.get("opnsense_instance", ""),
            gateway=metric["name"],
            wan=f"WAN{number}",
            number=number,
            iface_key=metric.get("interface", ""),
            device=metric.get("device", ""),
            family=metric.get("protocol", "inet"),
            dscp_name=dscp_name,
            tos=tos,
        ))
    return entries


def parse_monitors(status_results):
    """{firewall: {monitor addresses}} from opnsense_gateways_status rows."""
    monitors = {}
    for row in status_results:
        metric = row.get("metric", {})
        firewall = metric.get("opnsense_instance", "")
        address = metric.get("address")
        if firewall and address:
            monitors.setdefault(firewall, set()).add(address)
    return monitors


class Discovery:
    """Stateful discovery with removal grace and stale tracking."""

    def __init__(self, vm_query_url, removal_grace=900, clock=time.time, fetch=None):
        self.vm_query_url = vm_query_url
        self.removal_grace = removal_grace
        self.clock = clock
        self.fetch = fetch or (lambda expr: query(self.vm_query_url, expr))
        self.entries = {}        # key -> WanEntry
        self.last_seen = {}      # key -> timestamp
        self.monitors = {}       # firewall -> set(addresses)
        self.stale = {}          # firewall -> bool
        self.errors = []
        self.last_success = None

    def firewalls(self):
        return sorted({entry.firewall for entry in self.entries.values()})

    def refresh(self):
        """Query once; return the current desired entries (list)."""
        now = self.clock()
        self.errors = []
        try:
            info = self.fetch(INFO_QUERY)
            status = self.fetch(STATUS_QUERY)
        except Exception as exc:  # noqa: BLE001 — any failure keeps the last set
            self.errors.append(f"discovery query failed: {exc}")
            for firewall in self.firewalls():
                self.stale[firewall] = True
            return list(self.entries.values())

        self.last_success = now
        seen = parse_entries(info, self.errors)
        seen_keys = {entry.key for entry in seen}
        seen_firewalls = {entry.firewall for entry in seen}
        monitors = parse_monitors(status)

        # A firewall that had WANs and now reports none is treated as
        # missing data for that firewall, not as "all WANs removed".
        for firewall in self.firewalls():
            self.stale[firewall] = firewall not in seen_firewalls
        for entry in seen:
            self.entries[entry.key] = entry
            self.last_seen[entry.key] = now
            self.stale[entry.firewall] = False
            self.monitors[entry.firewall] = monitors.get(entry.firewall, set())

        for key in list(self.entries):
            if key in seen_keys:
                continue
            firewall = key[0]
            if self.stale.get(firewall):
                continue  # whole firewall missing: keep
            if now - self.last_seen.get(key, now) >= self.removal_grace:
                del self.entries[key]
                del self.last_seen[key]
        return list(self.entries.values())

    def targets_for(self, firewall, candidates):
        """Candidates minus that firewall's dpinger monitor addresses."""
        blocked = self.monitors.get(firewall, set())
        return [t for t in candidates if t["address"] not in blocked]
