#!/usr/bin/env python3
"""Unit tests for the WAN probe service — stdlib unittest, no network.

Run from the repo root: python3 -m unittest discover -s tests
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wan_probe import (
    config,  # noqa: E402
    discovery,  # noqa: E402
    dscp,  # noqa: E402
    isp,  # noqa: E402
    metrics,  # noqa: E402
    opnsense,  # noqa: E402
    prober,  # noqa: E402
)


def info_row(name, instance="cutlass", interface="opt12", device="ixl2", protocol="inet"):
    return {"metric": {"__name__": "opnsense_gateways_info", "name": name, "opnsense_instance": instance,
                       "interface": interface, "device": device, "protocol": protocol, "enabled": "true"},
            "value": [0, "1"]}


def status_row(name, address, instance="cutlass"):
    return {"metric": {"__name__": "opnsense_gateways_status", "name": name, "address": address,
                       "opnsense_instance": instance}, "value": [0, "1"]}


class DscpTests(unittest.TestCase):
    def test_class_selectors(self):
        self.assertEqual(dscp.allocate(1), ("cs1", 0x20))
        self.assertEqual(dscp.allocate(4), ("cs4", 0x80))
        self.assertEqual(dscp.allocate(7), ("cs7", 0xE0))

    def test_out_of_range(self):
        for bad in (0, 8, -1, "4"):
            with self.assertRaises(dscp.DscpError):
                dscp.allocate(bad)


class DiscoveryParseTests(unittest.TestCase):
    def test_gateway_names(self):
        self.assertEqual(discovery.wan_number("WAN"), 1)
        self.assertEqual(discovery.wan_number("WAN2_DHCP"), 2)
        self.assertEqual(discovery.wan_number("WAN4_DHCP"), 4)
        self.assertEqual(discovery.wan_number("WAN5_STATIC"), 5)
        self.assertIsNone(discovery.wan_number("WAN_EDGE"))
        self.assertIsNone(discovery.wan_number("Proton_GW"))
        self.assertIsNone(discovery.wan_number("WAN_DHCP6"))

    def test_parse_entries_cutlass_today(self):
        rows = [info_row("WAN", interface="wan", device="ixl0"),
                info_row("WAN2_DHCP", interface="opt7", device="re0"),
                info_row("WAN3_DHCP", interface="opt11", device="igc0"),
                info_row("WAN4_DHCP"),
                info_row("WAN_EDGE", interface="wan", device="ixl0"),
                info_row("Proton_GW", interface="opt8", device="wg0")]
        entries = discovery.parse_entries(rows)
        self.assertEqual([e.wan for e in entries], ["WAN1", "WAN2", "WAN3", "WAN4"])
        wan4 = entries[-1]
        self.assertEqual((wan4.gateway, wan4.iface_key, wan4.device, wan4.dscp_name, wan4.tos),
                         ("WAN4_DHCP", "opt12", "ixl2", "cs4", 0x80))
        self.assertEqual(wan4.key, ("cutlass", "WAN4", "inet"))

    def test_wan8_is_reported_not_silently_dropped(self):
        errors = []
        self.assertEqual(discovery.parse_entries([info_row("WAN8_DHCP")], errors), [])
        self.assertEqual(len(errors), 1)

    def test_monitors(self):
        monitors = discovery.parse_monitors([status_row("WAN4_DHCP", "1.0.0.1"), status_row("WAN", "8.8.4.4"),
                                             status_row("J", "9.9.9.9", instance="juno")])
        self.assertEqual(monitors, {"cutlass": {"1.0.0.1", "8.8.4.4"}, "juno": {"9.9.9.9"}})


class DiscoveryStateTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.rows = [info_row("WAN", interface="wan", device="ixl0"), info_row("WAN4_DHCP")]
        self.status = [status_row("WAN4_DHCP", "1.0.0.1")]
        self.fail = False

        def fetch(expr):
            if self.fail:
                raise RuntimeError("vm down")
            return self.rows if expr.startswith("opnsense_gateways_info") else self.status
        self.disc = discovery.Discovery("http://vm", removal_grace=900, clock=lambda: self.now, fetch=fetch)

    def test_discovers_and_filters_monitor_targets(self):
        entries = self.disc.refresh()
        self.assertEqual(sorted(e.wan for e in entries), ["WAN1", "WAN4"])
        targets = self.disc.targets_for("cutlass", [{"name": "a", "address": "1.0.0.1"},
                                                    {"name": "b", "address": "1.1.1.1"}])
        self.assertEqual([t["name"] for t in targets], ["b"])
        self.assertFalse(self.disc.stale["cutlass"])

    def test_query_failure_keeps_set_and_marks_stale(self):
        self.disc.refresh()
        self.fail = True
        self.now += 5000
        entries = self.disc.refresh()
        self.assertEqual(len(entries), 2)
        self.assertTrue(self.disc.stale["cutlass"])
        self.assertTrue(self.disc.errors)

    def test_removal_needs_grace(self):
        self.disc.refresh()
        self.rows = [info_row("WAN", interface="wan", device="ixl0")]
        self.now += 100
        self.assertEqual(len(self.disc.refresh()), 2, "absent for 100s: still kept")
        self.now += 900
        self.assertEqual([e.wan for e in self.disc.refresh()], ["WAN1"])

    def test_whole_firewall_missing_is_not_removal(self):
        self.disc.refresh()
        self.rows = []
        self.now += 5000
        self.assertEqual(len(self.disc.refresh()), 2)
        self.assertTrue(self.disc.stale["cutlass"])


class MetricsTests(unittest.TestCase):
    def test_render_gauge_counter_histogram(self):
        reg = metrics.Registry()
        g = reg.gauge("g", "a gauge", ("fw",))
        c = reg.counter("c", "a counter", ("fw",))
        h = reg.histogram("h", "a hist", ("fw",), buckets=(0.01, 0.1))
        g.set(1, "cutlass")
        c.inc("cutlass")
        c.inc("cutlass")
        h.observe(0.05, "cutlass")
        text = reg.render()
        self.assertIn('g{fw="cutlass"} 1\n', text)
        self.assertIn('c{fw="cutlass"} 2\n', text)
        self.assertIn('h_bucket{fw="cutlass",le="0.01"} 0\n', text)
        self.assertIn('h_bucket{fw="cutlass",le="0.1"} 1\n', text)
        self.assertIn('h_bucket{fw="cutlass",le="+Inf"} 1\n', text)
        self.assertIn('h_count{fw="cutlass"} 1\n', text)
        self.assertIn("# TYPE h histogram", text)

    def test_clear_where(self):
        reg = metrics.Registry()
        g = reg.gauge("g", "x", ("fw", "wan"))
        g.set(1, "cutlass", "WAN1")
        g.set(1, "cutlass", "WAN4")
        g.clear_where(lambda lab: lab["wan"] == "WAN4")
        self.assertEqual(list(g.series()), [("cutlass", "WAN1")])


class IspTests(unittest.TestCase):
    def test_query_roundtrip_a_and_txt(self):
        q = isp.build_query("myip.opendns.com", 1, 0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        self.assertIn(b"\x04myip\x07opendns\x03com\x00", q)
        # craft a response: header, echoed question, one A answer with a compressed name
        question = q[12:]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([149, 120, 62, 188])
        resp = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + answer
        self.assertEqual(isp.parse_answers(resp, 0x1234), ["149.120.62.188"])
        txt = b"\x05hello"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(txt)) + txt
        resp = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + answer
        self.assertEqual(isp.parse_answers(resp, 0x1234), ["hello"])

    def test_rcode_and_id_checks(self):
        resp = struct.pack("!HHHHHH", 1, 0x8183, 0, 0, 0, 0)
        with self.assertRaises(ValueError):
            isp.parse_answers(resp, 1)
        with self.assertRaises(ValueError):
            isp.parse_answers(struct.pack("!HHHHHH", 2, 0x8180, 0, 0, 0, 0), 1)

    def test_slug(self):
        self.assertEqual(isp.slug_from_org("TILLLMAN-FIBER-CO - TILLMAN FIBERCO, LLC, US"), "tillman")
        self.assertEqual(isp.slug_from_org("SPACEX-STARLINK, US"), "spacex")
        self.assertEqual(isp.slug_from_org(""), "unknown")


class RulesTests(unittest.TestCase):
    def setUp(self):
        self.fw = {"name": "cutlass", "node_interface": "opt2", "node_net": "10.0.20.0/23",
                   "private_alias": "RFC1918_Networks"}
        self.entries = discovery.parse_entries([info_row("WAN", interface="wan", device="ixl0"), info_row("WAN4_DHCP")])

    def test_desired_rule_shape(self):
        desired = opnsense.desired_rules(self.entries, self.fw, 10)
        self.assertEqual(len(desired), 2)
        (desc, rule), = [(d, r) for d, r in desired.items() if ":WAN4:" in d]
        self.assertTrue(desc.startswith("wan-probe:cutlass:WAN4:inet:"))
        self.assertEqual(rule["tos"], "cs4")
        self.assertEqual(rule["gateway"], "WAN4_DHCP")
        self.assertEqual(rule["sequence"], "14")
        self.assertEqual(rule["interface"], "opt2")
        self.assertEqual(rule["destination_not"], "1")
        self.assertEqual(rule["quick"], "1")
        self.assertEqual(rule["description"], desc)

    def test_description_changes_with_fields(self):
        a = opnsense.desired_rules(self.entries, self.fw, 10)
        b = opnsense.desired_rules(self.entries, dict(self.fw, node_net="10.0.20.0/24"), 10)
        self.assertEqual(set(a) & set(b), set())

    def test_plan_and_ownership(self):
        desired = opnsense.desired_rules(self.entries, self.fw, 10)
        rows = [{"uuid": "u1", "description": list(desired)[0]},
                {"uuid": "u2", "description": "wan-probe:cutlass:WAN9:inet:deadbeef"},
                {"uuid": "u3", "description": "Allow LAN out"}]
        actual = opnsense.owned_rules(rows)
        self.assertEqual(set(actual.values()), {"u1", "u2"}, "foreign rule u3 is never owned")
        to_add, to_delete = opnsense.plan(desired, actual)
        self.assertEqual(to_delete, ["u2"])
        self.assertEqual(to_add, [list(desired)[1]])

    def test_reconciler_applies_once_only_on_change(self):
        calls = []

        class FakeClient:
            def __init__(self, rows):
                self.rows = rows

            def call(self, path, payload=None):
                calls.append(path)
                if path.endswith("searchRule"):
                    return {"rows": self.rows}
                if path.endswith("addRule"):
                    self.rows.append({"uuid": "new", "description": payload["rule"]["description"]})
                    return {"result": "saved", "uuid": "new"}
                return {"status": "ok"}

        desired = opnsense.desired_rules(self.entries, self.fw, 10)
        client = FakeClient([])
        changed, managed = opnsense.Reconciler(client, "cutlass").reconcile(desired)
        self.assertTrue(changed)
        self.assertEqual(managed, 2)
        self.assertEqual(calls.count("/api/firewall/filter/apply"), 1)
        calls.clear()
        changed, managed = opnsense.Reconciler(client, "cutlass").reconcile(desired)
        self.assertFalse(changed)
        self.assertNotIn("/api/firewall/filter/apply", calls)


class ProberHelperTests(unittest.TestCase):
    def test_echo_packet_roundtrip(self):
        pkt = prober.echo_packet(42, stamp=1.5)
        seq, stamp = prober.parse_reply(pkt)
        self.assertEqual((seq, stamp), (42, 1.5))
        self.assertEqual(prober._checksum(pkt), 0)

    def test_errqueue_parse(self):
        ee = struct.pack("IBBBBII", 113, 2, 11, 0, 0, 0, 0) + struct.pack("HH4s", 2, 0, bytes([149, 120, 63, 1]))
        self.assertEqual(prober.parse_errqueue([(0, prober.IP_RECVERR, ee)]), (11, 0, "149.120.63.1"))
        self.assertEqual(prober.parse_errqueue([(0, 99, ee)]), (None, None, None))

    def test_first_hop_beyond_firewall(self):
        hops = [(1, "10.244.7.18", 0.0002, "ttl-exceeded"), (2, "10.0.20.1", 0.0006, "ttl-exceeded"),
                (3, "149.120.63.1", 0.0056, "ttl-exceeded"), (4, "1.1.1.1", 0.011, "reply")]
        self.assertEqual(prober.first_hop_beyond(hops, "10.0.20.1"), "149.120.63.1")
        self.assertEqual(prober.first_hop_beyond(hops, "10.0.99.1"), "149.120.63.1", "falls back to first public hop")
        self.assertIsNone(prober.first_hop_beyond(hops[:2], "10.0.20.1"))

    def test_steering_uniqueness(self):
        entries = discovery.parse_entries([info_row("WAN", interface="wan", device="ixl0"), info_row("WAN4_DHCP")])
        wan1, wan4 = entries
        st = prober.Steering()
        self.assertFalse(st.ok(wan4, entries))
        st.report(wan4, "149.120.63.1")
        st.report(wan1, "149.120.63.1")
        self.assertFalse(st.ok(wan4, entries), "both WANs on the same first hop = unsteered")
        st.report(wan1, "38.59.44.1")
        self.assertTrue(st.ok(wan4, entries))
        self.assertTrue(st.ok(wan1, entries))


class EventTests(unittest.TestCase):
    def test_emit_is_flat_json_without_none(self):
        import json
        import logging
        captured = []
        handler = logging.Handler()
        handler.emit = lambda record: captured.append(record.getMessage())
        events.log.addHandler(handler)
        self.addCleanup(events.log.removeHandler, handler)
        events.log.setLevel(logging.INFO)
        record = events.emit("wan_added", firewall="cutlass", wan="WAN4", previous=None, tos="0x80")
        self.assertEqual(record["event"], "wan_added")
        self.assertNotIn("previous", record)
        parsed = json.loads(captured[-1])
        self.assertEqual(parsed["wan"], "WAN4")
        self.assertIn("ts", parsed)


class ConfigTests(unittest.TestCase):
    def test_credentials_from_env(self):
        env = {"WAN_PROBE_CUTLASS_API_KEY": "k", "WAN_PROBE_CUTLASS_API_SECRET": "s"}
        self.assertEqual(config.credentials("cutlass", env), ("k", "s"))
        self.assertEqual(config.credentials("juno", env), (None, None))

    def test_load_merges_defaults(self):
        cfg = config.load(path="/nonexistent", env={})
        self.assertEqual(cfg["rules"]["enabled"], False)
        self.assertEqual(cfg["targets"]["inet"][0]["address"], "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
