"""Configuration for the WAN probe service.

One JSON file (ConfigMap, path in WAN_PROBE_CONFIG, default /config/config.json)
merged over the defaults below. Firewall API credentials never live in the
file: they come from the environment as WAN_PROBE_<FIREWALL>_API_KEY and
WAN_PROBE_<FIREWALL>_API_SECRET (firewall name upper-cased, dashes to
underscores). A firewall without credentials is still discovered and probed;
only rule reconciliation is skipped for it.

Design: plans/wan-probe-dscp-2026-10-17.md in the workspace.
"""
import copy
import json
import os

DEFAULTS = {
    # VictoriaMetrics instant-query endpoint; discovery reads the OPNsense
    # exporter's gateway series from here, never from the firewall.
    "vm_query_url": "http://vmsingle.victoria-metrics.svc.cluster.local.:8428/api/v1/query",
    "discovery_interval": 60,
    # A WAN must be absent from every successful discovery for this long
    # before its probes stop and its rule is removed. Missing data (query
    # failure, empty result for a firewall that had WANs) never counts.
    "removal_grace": 900,
    "firewalls": [],
    # Targets per family. Monitor addresses discovered from
    # opnsense_gateways_status are removed from this list per firewall at
    # runtime: a dpinger monitor target has a host route pinned to its own
    # WAN, so probing it says nothing about steering.
    "targets": {
        "inet": [
            {"name": "cloudflare", "address": "1.1.1.1"},
            {"name": "quad9", "address": "149.112.112.112"},
            {"name": "google", "address": "8.8.8.8"},
        ]
    },
    "ping_interval": 1.0,
    "ping_timeout": 1.0,
    "trace_interval": 60,
    "trace_timeout": 1.5,
    "trace_max_hops": 20,
    # Public-address and ASN lookups per WAN (section 4.1a of the plan).
    "isp_refresh": 3600,
    "isp_resolver": "208.67.222.222",
    "isp_name": "myip.opendns.com",
    # ISP slug overrides: {firewall: {wan: slug}}. The ASN organisation name
    # is the default (AS53366 reads "tillman"; the dashboards say tfiber).
    "isp_overrides": {},
    "rules": {
        "enabled": False,
        # Rules are created with sequence_base + wan_number so they sort as a
        # block; the block must sit above the node VLAN's general allow rule.
        "sequence_base": 10,
    },
    "listen": "0.0.0.0:9100",
}

FIREWALL_DEFAULTS = {
    "url": "",
    "verify_tls": False,
    # Address of the firewall on the VLAN the nodes sit on: the hop after it
    # in a path trace is the WAN gateway, which is what the steering check
    # compares across WANs.
    "node_gateway": "",
    # Internal interface key (optN) of that VLAN and its network, for the
    # rule API. Only needed when rules are enabled.
    "node_interface": "",
    "node_net": "",
    "private_alias": "RFC1918_Networks",
}


def _merge(base, override):
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def credentials(firewall_name, env=None):
    """(key, secret) for a firewall from the environment, or (None, None)."""
    env = os.environ if env is None else env
    slug = firewall_name.upper().replace("-", "_")
    key = env.get(f"WAN_PROBE_{slug}_API_KEY")
    secret = env.get(f"WAN_PROBE_{slug}_API_SECRET")
    if key and secret:
        return key, secret
    return None, None


def load(path=None, env=None):
    env = os.environ if env is None else env
    path = path or env.get("WAN_PROBE_CONFIG", "/config/config.json")
    data = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    cfg = _merge(DEFAULTS, data)
    firewalls = []
    for raw in cfg.get("firewalls", []):
        fw = _merge(FIREWALL_DEFAULTS, raw)
        if not fw.get("name"):
            raise ValueError("every firewall needs a name")
        fw["api_key"], fw["api_secret"] = credentials(fw["name"], env)
        firewalls.append(fw)
    cfg["firewalls"] = firewalls
    return cfg


def firewall(cfg, name):
    for fw in cfg["firewalls"]:
        if fw["name"] == name:
            return fw
    return None
