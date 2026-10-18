# wan-probe

Per-WAN ISP probing from Kubernetes, steered by DSCP marks the firewall routes on.

A multi-WAN OPNsense firewall can only tell you how its WANs are doing by
measuring from the firewall itself, and the measuring loads the firewall until
the numbers describe the firewall, not the ISPs. `wan-probe` moves the
measuring into the cluster: it discovers every WAN of every firewall, sends
ICMP echoes and path traces through each one, and marks every probe packet
with a DSCP class that one pf rule per WAN matches and routes to that WAN's
gateway. The firewall forwards packets and exports counters; it no longer
runs measurements.

```text
pod                 node (Cilium SNAT)     firewall, node VLAN rule            WAN
src 10.244.x.y  ──▶ src 10.0.21.n     ──▶ tos cs4 → route-to WAN4_DHCP  ──▶ src <WAN4 address>
tos 0x80            tos 0x80 (untouched)   (above the allow-any rule)         tos 0x80
```

## What it does

| Part | Does | Talks to |
| --- | --- | --- |
| discovery | every 60 s, reads `opnsense_gateways_info` (the [opnsense-exporter](https://github.com/AthennaMind/opnsense-exporter) series) and turns every gateway named `WAN[0-9]*` with an OPNsense suffix into a WAN; `WAN_EDGE`, VPN gateways and the like never match | the metrics store only |
| probers | one per WAN: ICMP echo at 1 Hz per target plus a TTL-stepped path trace every 60 s, on unprivileged datagram ICMP sockets (`net.ipv4.ping_group_range`, hop addresses from `IP_RECVERR`); every packet carries the WAN's DSCP | the internet, through that WAN |
| ISP identity | per WAN, hourly: one marked DNS query for the address the world sees, then Team Cymru's DNS ASN service; a slug per WAN, with overrides | OpenDNS, Team Cymru |
| rule reconciler | one `wan-probe:`-tagged pass rule per WAN through the OPNsense filter API, `apply` only when the set changes; off by default | the firewall API |
| HTTP | `/metrics`, `/livez`, `/healthz`, `/v1/firewalls`, `/v1/firewalls/<fw>/wans` | your scraper, you |

### The data-quality guard

A WAN publishes RTT, loss and hop series only while `wan_probe_steering_ok == 1`:
its first hop beyond the firewall is known and no other WAN of that firewall
shares it. Until the rules exist every WAN leaves on the default route, so the
service publishes presence, first hop and `steering_ok = 0` for them and
nothing else. When one WAN's rule is missing or shadowed, it lands on the
default-route WAN's first hop, so *both* go to 0: two blank WANs after a rule
change means one rule, not two faults.

Targets never include a dpinger monitor address (those have host routes pinned
to their own WAN, so they say nothing about steering); the service drops them
per firewall from `opnsense_gateways_status`.

### DSCP allocation

`WANn → CSn` (DSCP `8n`, TOS byte `32n`): `WAN`/`WAN1` → `cs1` (`0x20`),
`WAN2` → `cs2` (`0x40`) ... `WAN7` → `cs7`. Keyed on the number in the gateway
name, so a gateway rename keeps its mark. `WAN8` and above are refused and
reported, never wrapped.

## Deploy

Helm chart on GHCR, same version as the image:

```bash
helm install wan-probe oci://ghcr.io/bytelizard/charts/wan-probe --version 0.1.0 \
  --namespace wan-probe --create-namespace -f values.yaml
```

Minimal `values.yaml`:

```yaml
config:
  firewalls:
    - name: cutlass
      url: https://10.0.10.1          # OPNsense API, only used when rules are enabled
      node_gateway: 10.0.20.1         # the firewall's address on the VLAN the nodes use
      node_interface: opt2            # that VLAN's internal interface key (rules)
      node_net: 10.0.20.0/23          # that VLAN's network (rules)
      private_alias: RFC1918_Networks # alias the rules exclude as destination
  isp_overrides:
    cutlass: {WAN4: tfiber}
  rules:
    enabled: false
```

With Flux: an `OCIRepository` for `oci://ghcr.io/bytelizard/charts/wan-probe`
and a `HelmRelease` with `chartRef` pointing at it. Scrape
`<release>.<namespace>.svc:9100/metrics` every 15 s.

### Enabling the rules

1. On the firewall, an API user with *Firewall: Rules* (the API-driven filter
   model) and nothing else.
2. Credentials in the pod's environment as `WAN_PROBE_<FIREWALL>_API_KEY` /
   `WAN_PROBE_<FIREWALL>_API_SECRET` (upper-cased name, dashes to underscores):
   `credentials.existingSecret`, or `credentials.externalSecret` to have
   External Secrets Operator render them.
3. `config.rules.enabled: true` and `config.rules.sequence_base` low enough
   that `sequence_base + n` sorts above the node VLAN's general allow rule.

The reconciler owns only rules whose description starts with `wan-probe:`. A
changed desire is a delete plus an add (the description carries a hash of the
fields); `apply` runs once per reconcile and only when something changed.

## Configuration

`WAN_PROBE_CONFIG` (default `/config/config.json`) merges over these defaults:

| Key | Default | Meaning |
| --- | --- | --- |
| `vm_query_url` | `http://vmsingle.victoria-metrics.svc.cluster.local.:8428/api/v1/query` | Prometheus-compatible instant query endpoint |
| `discovery_interval` | `60` | seconds between discoveries |
| `removal_grace` | `900` | a WAN must be absent this long, across successful queries, before its probes stop and its rule goes; missing data never counts |
| `firewalls` | `[]` | see the values example above |
| `targets.inet` | Cloudflare `1.1.1.1`, Quad9 `149.112.112.112`, Google `8.8.8.8` | per family |
| `ping_interval` / `ping_timeout` | `1.0` / `1.0` | seconds |
| `trace_interval` / `trace_timeout` / `trace_max_hops` | `60` / `1.5` / `20` | |
| `isp_refresh` / `isp_resolver` / `isp_name` | `3600` / `208.67.222.222` / `myip.opendns.com` | public-address lookup |
| `isp_overrides` | `{}` | `{firewall: {wan: slug}}` |
| `rules.enabled` / `rules.sequence_base` | `false` / `10` | |
| `listen` | `0.0.0.0:9100` | |

## Metrics

Labels `firewall, wan, isp, family` (`target` where noted):

| Metric | Type | |
| --- | --- | --- |
| `wan_probe_wan_present{gateway,dscp,tos}` | gauge | 1 while discovered |
| `wan_probe_steering_ok` | gauge | 1 when this WAN's first hop is unique on its firewall |
| `wan_probe_first_hop{addr}` | gauge | first hop beyond the firewall |
| `wan_probe_isp_info{address,asn,org}` | gauge | what the world sees for this WAN |
| `wan_probe_rtt_seconds{target}` | histogram | only while steered |
| `wan_probe_sent_total` / `wan_probe_received_total{target}` | counter | only while steered |
| `wan_probe_hop_rtt_seconds{target,hop,hop_addr}` | gauge | latest trace, only while steered |
| `wan_probe_hop_reached{target}` | gauge | latest trace reached the target |
| `wan_probe_rules_in_sync{firewall}` | gauge | absent when rules are disabled |
| `wan_probe_rules_managed{firewall}` | gauge | |
| `wan_probe_discovery_stale{firewall}` | gauge | last query failed or was empty; last set kept |
| `wan_probe_discovery_errors_total` | counter | |

## API

```text
GET /v1/firewalls
{"firewalls": [{"name": "cutlass", "stale": false, "wans": ["WAN1", "WAN3", "WAN4"]}]}

GET /v1/firewalls/cutlass/wans
{"firewall": "cutlass", "wans": [
  {"wan": "WAN4", "gateway": "WAN4_DHCP", "family": "inet", "dscp": "cs4", "tos": "0x80",
   "interface": "opt12", "device": "ixl2", "isp": "tfiber", "address": "149.120.62.188",
   "asn": 53366, "org": "TILLLMAN-FIBER-CO - TILLMAN FIBERCO, LLC, US",
   "first_hop": "149.120.63.1", "steering_ok": true, "targets": ["cloudflare", "quad9", "google"]}]}
```

## Develop

Stdlib only; Python 3.13+.

```bash
make test          # python3 -m unittest discover -s tests
make lint          # ruff + compileall
make run           # WAN_PROBE_CONFIG=./config.json python3 -m wan_probe
make chart-lint
```

Release: `git tag v0.x.y && git push --tags` publishes the image and the chart.

## Requirements on the network

- The firewall must see the DSCP mark: Cilium's masquerade and pf's NAT
  rewrite the source address and leave the TOS byte alone (verified on
  OPNsense 26.7 with Cilium native routing).
- IPv4 today. Discovery already yields `inet6` gateways; IPv6 probing needs
  pods with routable IPv6, which is a cluster question before it is a probe one.
