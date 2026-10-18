"""Per-WAN probing on unprivileged ICMP datagram sockets.

One Prober per discovered (firewall, WAN, family). It owns two sockets, both
marked with the WAN's DSCP: one for continuous echoes (1/s per target) and
one for path traces (TTL-stepped echoes, hop addresses read from the error
queue via IP_RECVERR — the tracepath method, no raw socket, no capability).
Needs the safe sysctl net.ipv4.ping_group_range on the pod.

Measurements are published only while steering is confirmed for the entry
(see Steering); an unsteered WAN would otherwise publish another WAN's
numbers under its own label.
"""
import ipaddress
import logging
import select
import socket
import struct
import threading
import time

from . import series

log = logging.getLogger("wan-probe.prober")

IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
ICMP_ECHO = 8
ICMP_TIME_EXCEEDED = 11
ICMP_UNREACH = 3
PAYLOAD_TAG = b"wanprobe"


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def echo_packet(seq, stamp=None):
    payload = struct.pack("!d", stamp if stamp is not None else time.time()) + PAYLOAD_TAG
    header = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, 0, seq & 0xFFFF)
    return struct.pack("!BBHHH", ICMP_ECHO, 0, _checksum(header + payload), 0, seq & 0xFFFF) + payload


def parse_reply(data):
    """(seq, stamp) from an echo reply as delivered by a datagram ICMP socket."""
    if len(data) < 16:
        return None, None
    _type, _code, _csum, _ident, seq = struct.unpack("!BBHHH", data[:8])
    (stamp,) = struct.unpack("!d", data[8:16])
    return seq, stamp


def parse_errqueue(ancdata):
    """(icmp_type, icmp_code, offender_ip) from IP_RECVERR ancillary data."""
    for level, ctype, cdata in ancdata:
        if level == socket.IPPROTO_IP and ctype == IP_RECVERR and len(cdata) >= 24:
            _errno, origin, ee_type, ee_code, _pad, _info, _data = struct.unpack("IBBBBII", cdata[:16])
            _family, _port, raw = struct.unpack("HH4s", cdata[16:24])
            if origin == 2:  # SO_EE_ORIGIN_ICMP
                return ee_type, ee_code, socket.inet_ntoa(raw)
    return None, None, None


class IcmpSocket:
    def __init__(self, tos):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
        self.sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
        self.sock.setblocking(False)
        self.poller = select.poll()
        self.poller.register(self.sock, select.POLLIN | select.POLLERR)

    def close(self):
        self.sock.close()

    def send(self, target, seq, ttl=None):
        if ttl is not None:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        self.sock.sendto(echo_packet(seq), (target, 0))

    def events(self, timeout):
        """Yield ('reply', addr, seq, rtt) / ('error', dest, hop, type, code) until timeout."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            ready = self.poller.poll(int(remaining * 1000))
            if not ready:
                return
            for _fd, flags in ready:
                if flags & select.POLLERR:
                    try:
                        _data, anc, _flags, addr = self.sock.recvmsg(1500, 512, socket.MSG_ERRQUEUE)
                    except BlockingIOError:
                        continue
                    ee_type, ee_code, hop = parse_errqueue(anc)
                    if hop is not None:
                        yield ("error", addr[0], hop, ee_type, ee_code)
                if flags & select.POLLIN:
                    try:
                        data, addr = self.sock.recvfrom(1500)
                    except BlockingIOError:
                        continue
                    seq, stamp = parse_reply(data)
                    if seq is None:
                        continue
                    yield ("reply", addr[0], seq, max(0.0, time.time() - stamp))


def trace(sock, target, max_hops=20, timeout=1.5):
    """[(ttl, hop_addr|None, rtt_seconds|None, kind)] until the target answers."""
    hops = []
    for ttl in range(1, max_hops + 1):
        started = time.time()
        sock.send(target, ttl, ttl=ttl)
        hop, kind, rtt = None, "timeout", None
        for event in sock.events(timeout):
            if event[0] == "reply" and event[1] == target:
                hop, kind, rtt = target, "reply", event[3]
                break
            if event[0] == "error" and event[1] == target:
                hop, rtt = event[2], time.time() - started
                kind = "ttl-exceeded" if event[3] == ICMP_TIME_EXCEEDED else "unreachable"
                break
        hops.append((ttl, hop, rtt, kind))
        if kind in ("reply", "unreachable"):
            break
    return hops


def first_hop_beyond(hops, firewall_address):
    """Address of the hop after the firewall, else the first public hop."""
    addresses = [hop for _ttl, hop, _rtt, _kind in hops if hop]
    if firewall_address in addresses:
        index = addresses.index(firewall_address)
        if index + 1 < len(addresses):
            return addresses[index + 1]
        return None
    for address in addresses:
        try:
            if ipaddress.ip_address(address).is_global:
                return address
        except ValueError:
            continue
    return None


class Steering:
    """Which WANs are proven to leave on their own first hop."""

    def __init__(self):
        self._first_hop = {}   # entry.key -> address
        self._lock = threading.Lock()

    def report(self, entry, address):
        with self._lock:
            previous = self._first_hop.get(entry.key)
            self._first_hop[entry.key] = address
        if previous != address:
            log.info("%s/%s first hop %s -> %s", entry.firewall, entry.wan, previous, address)

    def forget(self, key):
        with self._lock:
            self._first_hop.pop(key, None)

    def first_hop(self, key):
        with self._lock:
            return self._first_hop.get(key)

    def ok(self, entry, siblings):
        """True when entry's first hop is known and unique among its firewall's WANs."""
        with self._lock:
            mine = self._first_hop.get(entry.key)
            if mine is None:
                return False
            for other in siblings:
                if other.key != entry.key and self._first_hop.get(other.key) == mine:
                    return False
            return True


class Prober(threading.Thread):
    def __init__(self, entry, targets, cfg, steering, siblings, firewall_cfg, identify=None):
        super().__init__(name=f"probe-{entry.firewall}-{entry.wan}", daemon=True)
        self.entry = entry
        self.targets = list(targets)
        self.cfg = cfg
        self.steering = steering
        self.siblings = siblings            # callable -> current entries of this firewall
        self.firewall_cfg = firewall_cfg
        self.identify = identify            # callable(tos) -> {address, asn, org, isp}
        self.isp = "unknown"
        self.identity = {}
        self._stop = threading.Event()
        self._last_trace = 0.0
        self._last_identify = 0.0
        self._published = False

    @property
    def labels(self):
        return (self.entry.firewall, self.entry.wan, self.isp, self.entry.family)

    def _mine(self, target=None):
        """Predicate: series labels belonging to this entry (and target)."""
        entry = self.entry

        def match(lab):
            return (lab["firewall"] == entry.firewall and lab["wan"] == entry.wan
                    and lab["family"] == entry.family and (target is None or lab["target"] == target))
        return match

    def stop(self):
        self._stop.set()

    def steered(self):
        if not self.targets:
            return False
        siblings = self.siblings()
        if len(siblings) <= 1:
            return self.steering.first_hop(self.entry.key) is not None
        return self.steering.ok(self.entry, siblings)

    def _publish_state(self):
        ok = self.steered()
        series.steering_ok.set(1 if ok else 0, *self.labels)
        hop = self.steering.first_hop(self.entry.key)
        series.first_hop.clear_where(self._mine())
        if hop:
            series.first_hop.set(1, *self.labels, hop)
        if not ok and self._published:
            series.drop_measurements({"firewall": self.entry.firewall, "wan": self.entry.wan,
                                      "family": self.entry.family})
            self._published = False
        return ok

    def _set_isp(self, slug):
        if slug == self.isp:
            return
        old = {"firewall": self.entry.firewall, "wan": self.entry.wan, "family": self.entry.family, "isp": self.isp}
        series.drop_entry(old)
        self.isp = slug
        self._published = False

    def _maybe_identify(self, now):
        if not self.identify or now - self._last_identify < self.cfg["isp_refresh"]:
            return
        if not self.steered():
            return  # the lookup leaves on the default route and would name the wrong ISP
        self._last_identify = now
        try:
            info = self.identify(self.entry.tos)
        except Exception as exc:  # noqa: BLE001 — identity is best effort
            log.warning("%s/%s identify failed: %s", self.entry.firewall, self.entry.wan, exc)
            return
        self.identity = info
        self._set_isp(info.get("isp") or "unknown")
        series.isp_info.clear_where(self._mine())
        series.isp_info.set(1, *self.labels, info.get("address") or "", info.get("asn") or "", info.get("org") or "")

    def _trace_round(self, sock):
        for target in self.targets:
            hops = trace(sock, target["address"], self.cfg["trace_max_hops"], self.cfg["trace_timeout"])
            self.steering.report(self.entry, first_hop_beyond(hops, self.firewall_cfg.get("node_gateway", "")))
            if not self._publish_state():
                continue
            labels = self.labels + (target["name"],)
            series.hop_rtt_seconds.clear_where(self._mine(target["name"]))
            reached = 0
            for ttl, hop, rtt, kind in hops:
                if hop and rtt is not None:
                    series.hop_rtt_seconds.set(rtt, *labels, ttl, hop)
                if kind == "reply":
                    reached = 1
            series.hop_reached.set(reached, *labels)
            self._published = True

    def _ping_round(self, sock, seq):
        pending = {}
        for target in self.targets:
            sock.send(target["address"], seq)
            pending[target["address"]] = target["name"]
        results = {}
        for event in sock.events(self.cfg["ping_timeout"]):
            if event[0] == "reply" and event[2] == seq and event[1] in pending:
                results[event[1]] = event[3]
            elif event[0] == "error" and event[1] in pending:
                results.setdefault(event[1], None)
            if len(results) == len(pending):
                break
        if not self._publish_state():
            return
        for address, name in pending.items():
            labels = self.labels + (name,)
            series.sent_total.inc(*labels)
            rtt = results.get(address)
            if rtt is not None:
                series.received_total.inc(*labels)
                series.rtt_seconds.observe(rtt, *labels)
        self._published = True

    def run(self):
        ping_sock = IcmpSocket(self.entry.tos)
        trace_sock = IcmpSocket(self.entry.tos)
        seq = 0
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                self._maybe_identify(now)
                if now - self._last_trace >= self.cfg["trace_interval"]:
                    self._last_trace = now
                    self._trace_round(trace_sock)
                seq = (seq + 1) & 0xFFFF
                started = time.monotonic()
                self._ping_round(ping_sock, seq)
                self._stop.wait(max(0.0, self.cfg["ping_interval"] - (time.monotonic() - started)))
        except Exception:  # noqa: BLE001 — a crashed prober must be visible, not silent
            log.exception("%s/%s prober died", self.entry.firewall, self.entry.wan)
        finally:
            ping_sock.close()
            trace_sock.close()
