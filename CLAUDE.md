# CLAUDE.md — wan-probe

Per-WAN ISP probing from Kubernetes, steered by DSCP. One stdlib-only Python
service: discovers WANs from the OPNsense exporter's series in the metrics
store, probes each WAN from the cluster with ICMP echoes and path traces whose
packets carry that WAN's DSCP class, keeps one pf rule per WAN on the firewall
that routes by that class, and exposes Prometheus metrics plus a small HTTP
API. First-party image `ghcr.io/bytelizard/wan-probe`, chart
`oci://ghcr.io/bytelizard/charts/wan-probe`, deployed by
`kube-apps/apps/wan-probe/` (Flux HelmRelease).

Read [README.md](README.md) for what it does and how it is configured.

## Layout
- `wan_probe/` — the package. `main.py` is the loop (discovery → probers →
  rules → API state); `discovery.py` (metrics-store queries, grace, stale);
  `dscp.py` (WANn → CSn); `prober.py` (unprivileged ICMP echo + error-queue
  traces, the steering check); `isp.py` (marked DNS + Team Cymru ASN);
  `opnsense.py` (filter-API reconciler); `series.py` (every metric, the
  contract); `metrics.py` (text exposition); `api.py` (HTTP); `config.py`.
- `tests/` — stdlib `unittest`, no network. `make test`.
- `charts/wan-probe/` — the Helm chart; versioned from the git tag at release.
- `Dockerfile` — single stage on `python:3.15-alpine`, runs as nobody.

## How we work
- **The guard is the product.** Nothing about a WAN is published as RTT, loss
  or hops unless `steering_ok` proves the packets left on that WAN. Any change
  that could publish a number under the wrong WAN label is a bug, not a
  trade-off.
- **Never touch the firewall on the hot path.** Discovery reads the metrics
  store; the firewall API is called only by the reconciler, only when the WAN
  set changes, and `apply` at most once per pass.
- **Stdlib only.** No runtime dependencies: the image is the interpreter plus
  this package. Keep it that way unless a dependency buys something the
  stdlib cannot do.
- **Monitor addresses are never targets.** A dpinger monitor address has a
  host route pinned to its WAN; probing it says nothing about steering.
- **Pin versions; let Renovate bump them.** `# renovate:` hint on the
  Dockerfile base image; action versions pinned.
- **Secrets** come from the environment only (`WAN_PROBE_<FW>_API_KEY` /
  `_API_SECRET`); in-cluster they render from OpenBao via External Secrets
  Operator through the chart's `credentials.externalSecret`. Never commit values.

## CI
`ci.yaml`: ruff + unit tests and `helm lint`/`helm template` on
`runs-on: homelab`; the buildx smoke build on `ubuntu-latest`.
`release.yaml`: push to `main` publishes `:main` and `:sha-*` images; a `v*`
tag publishes semver image tags and the chart at the same version. Release =
`git tag v0.x.y && git push --tags`; Renovate PRs the bump into kube-apps.

## Commits / PRs
Branch off `main`; one concern per PR; conventional-ish subjects
(`feat:`, `fix:`, `chart:`, `ci:` …). Merge on green.

## Agent skills

### Issue tracker

Before ticket work, read `docs/agents/issue-tracker.md`.
Work is tracked in Windshift, Homelab workspace (`HO`).

### Triage labels

Before triage, read `docs/agents/triage-labels.md`.
Use the five standard triage roles.

### Domain docs

Before codebase exploration, read `docs/agents/domain.md`.
Use a single-context glossary and ADR layout.
