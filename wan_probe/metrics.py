"""Minimal Prometheus text-exposition registry (stdlib only).

Gauge, Counter and Histogram with label sets; render() produces the text
format vmagent scrapes. Series can be dropped again (remove/clear_labels),
which the probe uses when a WAN disappears or loses steering: a stale
series must vanish, not freeze.
"""
import math
import threading


def _fmt(value):
    if value == math.inf:
        return "+Inf"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return repr(value) if isinstance(value, float) else str(value)


def _labels(names, values):
    if len(names) != len(values):
        raise ValueError(f"expected labels {names}, got {values}")
    if not names:
        return ""
    parts = []
    for name, value in zip(names, values, strict=True):
        text = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        parts.append(f'{name}="{text}"')
    return "{" + ",".join(parts) + "}"


class _Metric:
    kind = ""

    def __init__(self, name, help_text, labelnames=()):
        self.name = name
        self.help = help_text
        self.labelnames = tuple(labelnames)
        self._values = {}
        self._lock = threading.Lock()

    def remove(self, *labelvalues):
        with self._lock:
            self._values.pop(tuple(str(v) for v in labelvalues), None)

    def clear_where(self, predicate):
        """Drop every series whose label dict satisfies predicate."""
        with self._lock:
            for key in list(self._values):
                if predicate(dict(zip(self.labelnames, key, strict=True))):
                    del self._values[key]

    def series(self):
        with self._lock:
            return dict(self._values)

    def _header(self):
        return f"# HELP {self.name} {self.help}\n# TYPE {self.name} {self.kind}\n"


class Gauge(_Metric):
    kind = "gauge"

    def set(self, value, *labelvalues):
        with self._lock:
            self._values[tuple(str(v) for v in labelvalues)] = float(value)

    def render(self):
        out = [self._header()]
        for key, value in sorted(self.series().items()):
            out.append(f"{self.name}{_labels(self.labelnames, key)} {_fmt(value)}\n")
        return "".join(out)


class Counter(_Metric):
    kind = "counter"

    def inc(self, *labelvalues, amount=1):
        key = tuple(str(v) for v in labelvalues)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def render(self):
        out = [self._header()]
        for key, value in sorted(self.series().items()):
            out.append(f"{self.name}{_labels(self.labelnames, key)} {_fmt(value)}\n")
        return "".join(out)


class Histogram(_Metric):
    kind = "histogram"

    def __init__(self, name, help_text, labelnames=(), buckets=()):
        super().__init__(name, help_text, labelnames)
        self.buckets = tuple(sorted(buckets)) + (math.inf,)

    def observe(self, value, *labelvalues):
        key = tuple(str(v) for v in labelvalues)
        with self._lock:
            entry = self._values.get(key)
            if entry is None:
                entry = {"counts": [0] * len(self.buckets), "sum": 0.0, "count": 0}
                self._values[key] = entry
            for index, bound in enumerate(self.buckets):
                if value <= bound:
                    entry["counts"][index] += 1
            entry["sum"] += value
            entry["count"] += 1

    def render(self):
        out = [self._header()]
        for key, entry in sorted(self.series().items()):
            for bound, count in zip(self.buckets, entry["counts"], strict=True):
                labels = _labels(self.labelnames + ("le",), key + (_fmt(bound),))
                out.append(f"{self.name}_bucket{labels} {count}\n")
            labels = _labels(self.labelnames, key)
            out.append(f"{self.name}_sum{labels} {_fmt(entry['sum'])}\n")
            out.append(f"{self.name}_count{labels} {entry['count']}\n")
        return "".join(out)


class Registry:
    def __init__(self):
        self._metrics = []

    def gauge(self, name, help_text, labelnames=()):
        metric = Gauge(name, help_text, labelnames)
        self._metrics.append(metric)
        return metric

    def counter(self, name, help_text, labelnames=()):
        metric = Counter(name, help_text, labelnames)
        self._metrics.append(metric)
        return metric

    def histogram(self, name, help_text, labelnames=(), buckets=()):
        metric = Histogram(name, help_text, labelnames, buckets)
        self._metrics.append(metric)
        return metric

    def render(self):
        return "".join(metric.render() for metric in self._metrics)


# RTT buckets in seconds: sub-millisecond LAN up to multi-second stalls.
RTT_BUCKETS = (0.001, 0.002, 0.005, 0.01, 0.015, 0.02, 0.03, 0.05, 0.075, 0.1,
               0.15, 0.25, 0.5, 1.0, 2.0)
