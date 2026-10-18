# Single-stage: the service is stdlib-only Python, nothing to compile.
# renovate: datasource=docker depName=python
FROM python:3.15-alpine

LABEL org.opencontainers.image.source="https://github.com/ByteLizard/wan-probe" \
      org.opencontainers.image.description="Per-WAN ISP probing from Kubernetes, steered by DSCP" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WAN_PROBE_CONFIG=/config/config.json

WORKDIR /app
COPY wan_probe/ ./wan_probe/

# nobody: the probes use unprivileged ICMP datagram sockets (the pod sets
# net.ipv4.ping_group_range); no capability, no root, no writable filesystem.
USER 65534:65534
EXPOSE 9100
ENTRYPOINT ["python3", "-m", "wan_probe"]
