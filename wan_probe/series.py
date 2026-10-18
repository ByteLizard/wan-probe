"""Every metric the service exposes, in one place (names are the contract)."""
from .metrics import RTT_BUCKETS, Registry

registry = Registry()

ENTRY = ("firewall", "wan", "isp", "family")
TARGET = ENTRY + ("target",)

wan_present = registry.gauge(
    "wan_probe_wan_present",
    "1 while the WAN is discovered on the firewall (labels carry its gateway, DSCP class and tos byte)",
    ENTRY + ("gateway", "dscp", "tos"))
steering_ok = registry.gauge(
    "wan_probe_steering_ok",
    "1 when this WAN's probes leave on a first hop no other WAN of the firewall shares; 0 = rule missing or shadowed",
    ENTRY)
first_hop = registry.gauge(
    "wan_probe_first_hop",
    "1 for the address seen as the first hop beyond the firewall for this WAN",
    ENTRY + ("addr",))
isp_info = registry.gauge(
    "wan_probe_isp_info",
    "1 with the public address and ASN the WAN is seen as (learned through the WAN)",
    ENTRY + ("address", "asn", "org"))
rtt_seconds = registry.histogram(
    "wan_probe_rtt_seconds",
    "Echo round-trip time per target through this WAN (only while steering_ok)",
    TARGET, buckets=RTT_BUCKETS)
sent_total = registry.counter(
    "wan_probe_sent_total", "Echo requests sent (only while steering_ok)", TARGET)
received_total = registry.counter(
    "wan_probe_received_total", "Echo replies received (only while steering_ok)", TARGET)
hop_rtt_seconds = registry.gauge(
    "wan_probe_hop_rtt_seconds",
    "Latest path-trace round-trip time per hop (only while steering_ok)",
    TARGET + ("hop", "hop_addr"))
hop_reached = registry.gauge(
    "wan_probe_hop_reached",
    "1 when the latest path trace reached the target (only while steering_ok)",
    TARGET)
rules_in_sync = registry.gauge(
    "wan_probe_rules_in_sync",
    "1 when the firewall's wan-probe rules match the discovered WANs; 0 after a failed reconcile; "
    "absent when rules are disabled",
    ("firewall",))
rules_managed = registry.gauge(
    "wan_probe_rules_managed", "Number of wan-probe rules present on the firewall", ("firewall",))
discovery_stale = registry.gauge(
    "wan_probe_discovery_stale",
    "1 when the last discovery query failed or returned nothing for this firewall; the last known WAN set is kept",
    ("firewall",))
discovery_errors_total = registry.counter(
    "wan_probe_discovery_errors_total", "Discovery queries that failed", ())
build_info = registry.gauge("wan_probe_build_info", "Service version", ("version",))


def drop_entry(labels):
    """Remove every series belonging to one (firewall, wan, family)."""
    def match(series_labels):
        return all(series_labels.get(k) == v for k, v in labels.items())
    for metric in (wan_present, steering_ok, first_hop, isp_info, rtt_seconds, sent_total,
                   received_total, hop_rtt_seconds, hop_reached):
        metric.clear_where(match)


def drop_measurements(labels):
    """Remove only the steered-only series (RTT, counters, hops) of an entry."""
    def match(series_labels):
        return all(series_labels.get(k) == v for k, v in labels.items())
    for metric in (rtt_seconds, sent_total, received_total, hop_rtt_seconds, hop_reached):
        metric.clear_where(match)
