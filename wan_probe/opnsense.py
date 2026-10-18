"""OPNsense filter-rule reconciliation: one pass rule per WAN, by DSCP.

The service owns only rules whose description starts with "wan-probe:".
A rule's description carries a short hash of its fields, so a changed
desire is a delete + add, never an in-place edit, and the comparison needs
no round trip through the API's option-map responses. `apply` runs once
per reconcile and only when something changed: a pf reload is itself a
stall source on the firewall.
"""
import base64
import hashlib
import json
import logging
import ssl
import urllib.request

log = logging.getLogger("wan-probe.rules")

TAG = "wan-probe:"


class Client:
    def __init__(self, url, key, secret, verify_tls=False, timeout=30):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.auth = base64.b64encode(f"{key}:{secret}".encode()).decode()
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def call(self, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.url + path, data=data, method="POST" if payload is not None else "GET",
            headers={"Authorization": "Basic " + self.auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
            return json.load(resp)


def rule_fields(entry, firewall_cfg, sequence_base):
    """The filter-rule payload for one WAN entry, without its description."""
    return {
        "enabled": "1",
        "sequence": str(sequence_base + entry.number),
        "action": "pass",
        "quick": "1",
        "interface": firewall_cfg["node_interface"],
        "direction": "in",
        "ipprotocol": entry.family,
        "protocol": "any",
        "source_net": firewall_cfg["node_net"],
        "destination_net": firewall_cfg["private_alias"],
        "destination_not": "1",
        "gateway": entry.gateway,
        "tos": entry.dscp_name,
        "log": "0",
    }


def description_for(entry, fields):
    digest = hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:8]
    return f"{TAG}{entry.firewall}:{entry.wan}:{entry.family}:{digest}"


def desired_rules(entries, firewall_cfg, sequence_base):
    """{description: payload} for every entry of one firewall."""
    out = {}
    for entry in entries:
        fields = rule_fields(entry, firewall_cfg, sequence_base)
        description = description_for(entry, fields)
        out[description] = dict(fields, description=description)
    return out


def owned_rules(rows):
    """{description: uuid} for rows the service owns."""
    out = {}
    for row in rows:
        description = row.get("description", "") or ""
        if description.startswith(TAG) and row.get("uuid"):
            out[description] = row["uuid"]
    return out


def plan(desired, actual):
    """(to_add descriptions, to_delete uuids)."""
    to_add = [d for d in desired if d not in actual]
    to_delete = [uuid for d, uuid in actual.items() if d not in desired]
    return to_add, to_delete


class Reconciler:
    def __init__(self, client, firewall_name):
        self.client = client
        self.firewall = firewall_name

    def list_owned(self):
        resp = self.client.call("/api/firewall/filter/searchRule",
                                {"searchPhrase": TAG, "rowCount": 500, "current": 1})
        return owned_rules(resp.get("rows", []))

    def reconcile(self, desired):
        """Apply the plan; return (changed, managed_count)."""
        actual = self.list_owned()
        to_add, to_delete = plan(desired, actual)
        for uuid in to_delete:
            self.client.call(f"/api/firewall/filter/delRule/{uuid}", {})
            log.info("%s: deleted rule %s", self.firewall, uuid)
        for description in to_add:
            resp = self.client.call("/api/firewall/filter/addRule", {"rule": desired[description]})
            if resp.get("result") != "saved":
                raise RuntimeError(f"addRule rejected: {resp}")
            log.info("%s: added rule %s", self.firewall, description)
        changed = bool(to_add or to_delete)
        if changed:
            resp = self.client.call("/api/firewall/filter/apply", {})
            log.info("%s: applied filter rules: %s", self.firewall, resp)
        return changed, len(self.list_owned()) if changed else len(actual)
