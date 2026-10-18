"""HTTP surface: /metrics, /livez (process up), /healthz (discovery has succeeded),
/v1/firewalls, /v1/firewalls/<fw>/wans."""
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import series

log = logging.getLogger("wan-probe.api")


class State:
    """What the main loop knows, read by the API. Probe-side fields (first hop,
    steering, ISP) are read live from the probers so the API never lags a
    discovery interval behind the metrics."""

    def __init__(self):
        self._lock = threading.Lock()
        self._entries = []
        self._probers = {}
        self._stale = {}
        self.healthy = False

    def update(self, entries, probers, discovery):
        with self._lock:
            self._entries = list(entries)
            self._probers = dict(probers)
            self._stale = dict(discovery.stale)

    @staticmethod
    def _describe(entry, prober):
        identity = prober.identity if prober else {}
        return {
            "firewall": entry.firewall,
            "gateway": entry.gateway,
            "wan": entry.wan,
            "family": entry.family,
            "dscp": entry.dscp_name,
            "tos": f"0x{entry.tos:02x}",
            "interface": entry.iface_key,
            "device": entry.device,
            "isp": prober.isp if prober else "unknown",
            "address": identity.get("address"),
            "asn": identity.get("asn"),
            "org": identity.get("org"),
            "first_hop": prober.steering.first_hop(entry.key) if prober else None,
            "steering_ok": bool(prober and prober.steered()),
            "targets": [t["name"] for t in prober.targets] if prober else [],
        }

    def firewalls(self):
        with self._lock:
            names = sorted({e.firewall for e in self._entries} | set(self._stale))
            return [{"name": n, "stale": bool(self._stale.get(n)),
                     "wans": sorted(e.wan for e in self._entries if e.firewall == n)}
                    for n in names]

    def wans(self, firewall):
        with self._lock:
            pairs = [(e, self._probers.get(e.key)) for e in self._entries if e.firewall == firewall]
        return sorted((self._describe(e, p) for e, p in pairs), key=lambda w: (w["wan"], w["family"]))


class Handler(BaseHTTPRequestHandler):
    state = None  # set by serve()

    def log_message(self, fmt, *args):  # quiet access log
        log.debug(fmt, *args)

    def _send(self, code, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 — http.server API
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/metrics":
            return self._send(200, series.registry.render().encode(), "text/plain; version=0.0.4")
        if path == "/livez":
            return self._send(200, {"ok": True})
        if path == "/healthz":
            return self._send(200 if self.state.healthy else 503, {"ok": self.state.healthy})
        if path == "/v1/firewalls":
            return self._send(200, {"firewalls": self.state.firewalls()})
        parts = path.split("/")
        if len(parts) == 5 and parts[1:3] == ["v1", "firewalls"] and parts[4] == "wans":
            wans = self.state.wans(parts[3])
            if not wans and parts[3] not in [f["name"] for f in self.state.firewalls()]:
                return self._send(404, {"error": "unknown firewall"})
            return self._send(200, {"firewall": parts[3], "wans": wans})
        return self._send(404, {"error": "not found"})


def serve(state, listen):
    host, _, port = listen.rpartition(":")
    Handler.state = state
    server = ThreadingHTTPServer((host or "0.0.0.0", int(port)), Handler)
    thread = threading.Thread(target=server.serve_forever, name="api", daemon=True)
    thread.start()
    return server
