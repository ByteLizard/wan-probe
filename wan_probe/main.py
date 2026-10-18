#!/usr/bin/env python3
"""WAN probe service: discover WANs, keep their steering rules, probe them.

Loop every discovery_interval:
  entries = discovery.refresh()          # from VictoriaMetrics, with grace
  start/stop one Prober per entry        # ping + trace with the WAN's DSCP
  reconcile firewall rules (if enabled)  # one pass rule per WAN, by DSCP
  publish presence / stale / sync gauges
"""
import logging
import os
import time

from . import __version__, api, config, isp, opnsense, series
from . import discovery as discovery_mod
from . import prober as prober_mod

log = logging.getLogger("wan-probe")


def entry_labels(entry, isp_slug):
    return (entry.firewall, entry.wan, isp_slug, entry.family)


def reconcile_rules(cfg, disc, entries, clients):
    if not cfg["rules"]["enabled"]:
        return
    by_firewall = {}
    for entry in entries:
        by_firewall.setdefault(entry.firewall, []).append(entry)
    for firewall_name, fw_entries in by_firewall.items():
        fw_cfg = config.firewall(cfg, firewall_name)
        if not fw_cfg or not fw_cfg.get("api_key"):
            log.warning("%s: rules enabled but no credentials or config; skipping", firewall_name)
            continue
        if not fw_cfg.get("node_interface") or not fw_cfg.get("node_net"):
            log.warning("%s: rules enabled but node_interface/node_net unset; skipping", firewall_name)
            continue
        if disc.stale.get(firewall_name):
            log.info("%s: discovery stale, leaving rules untouched", firewall_name)
            continue
        client = clients.get(firewall_name)
        if client is None:
            client = clients[firewall_name] = opnsense.Client(
                fw_cfg["url"], fw_cfg["api_key"], fw_cfg["api_secret"], fw_cfg["verify_tls"])
        desired = opnsense.desired_rules(fw_entries, fw_cfg, cfg["rules"]["sequence_base"])
        try:
            _changed, managed = opnsense.Reconciler(client, firewall_name).reconcile(desired)
            series.rules_in_sync.set(1, firewall_name)
            series.rules_managed.set(managed, firewall_name)
        except Exception as exc:  # noqa: BLE001 — surface, keep probing
            log.error("%s: rule reconcile failed: %s", firewall_name, exc)
            series.rules_in_sync.set(0, firewall_name)


def main():
    logging.basicConfig(level=os.environ.get("WAN_PROBE_LOG", "INFO"),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    cfg = config.load()
    series.build_info.set(1, __version__)
    disc = discovery_mod.Discovery(cfg["vm_query_url"], cfg["removal_grace"])
    steering = prober_mod.Steering()
    state = api.State()
    api.serve(state, cfg["listen"])
    probers = {}
    clients = {}
    current = []

    def siblings_of(firewall_name):
        return lambda: [e for e in current if e.firewall == firewall_name]

    def identify_for(firewall_name, wan):
        override = cfg["isp_overrides"].get(firewall_name, {}).get(wan)
        return lambda tos: isp.identify(tos, override, cfg["isp_resolver"], cfg["isp_name"])

    log.info("wan-probe %s starting; firewalls configured: %s; rules %s",
             __version__, [f["name"] for f in cfg["firewalls"]],
             "enabled" if cfg["rules"]["enabled"] else "disabled")

    while True:
        started = time.monotonic()
        current = disc.refresh()
        if disc.errors:
            for error in disc.errors:
                log.warning(error)
            series.discovery_errors_total.inc(amount=len(disc.errors))
        for firewall_name in disc.firewalls():
            series.discovery_stale.set(1 if disc.stale.get(firewall_name) else 0, firewall_name)

        wanted = {entry.key: entry for entry in current}
        for key in list(probers):
            if key not in wanted:
                probers[key].stop()
                old = probers.pop(key)
                steering.forget(key)
                series.drop_entry({"firewall": key[0], "wan": key[1], "family": key[2]})
                log.info("%s/%s removed", old.entry.firewall, old.entry.wan)
        for key, entry in wanted.items():
            fw_cfg = config.firewall(cfg, entry.firewall) or dict(config.FIREWALL_DEFAULTS, name=entry.firewall)
            targets = disc.targets_for(entry.firewall, cfg["targets"].get(entry.family, []))
            changed = key in probers and (
                probers[key].entry != entry
                or [t["address"] for t in probers[key].targets] != [t["address"] for t in targets])
            if changed:
                probers[key].stop()
                probers.pop(key)
            if key not in probers:
                probers[key] = prober_mod.Prober(entry, targets, cfg, steering, siblings_of(entry.firewall),
                                                 fw_cfg, identify_for(entry.firewall, entry.wan))
                probers[key].start()
                log.info("%s/%s probing via %s (%s, tos 0x%02x) targets=%s", entry.firewall, entry.wan,
                         entry.gateway, entry.dscp_name, entry.tos, [t["name"] for t in targets])
            series.wan_present.clear_where(
                lambda lab, e=entry: (lab["firewall"] == e.firewall and lab["wan"] == e.wan
                                      and lab["family"] == e.family))
            series.wan_present.set(1, *entry_labels(entry, probers[key].isp), entry.gateway, entry.dscp_name,
                                   f"0x{entry.tos:02x}")

        reconcile_rules(cfg, disc, current, clients)
        state.update(current, probers, disc)
        state.healthy = disc.last_success is not None
        time.sleep(max(1.0, cfg["discovery_interval"] - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
