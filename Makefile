SHELL := /bin/bash
IMAGE ?= ghcr.io/bytelizard/wan-probe
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: test lint run image chart-lint chart-template

test: ## stdlib unittest, no network
	python3 -m unittest discover -s tests

lint:
	ruff check .
	python3 -m compileall -q wan_probe

run: ## local run against a config file (WAN_PROBE_CONFIG=./config.json)
	WAN_PROBE_CONFIG=$${WAN_PROBE_CONFIG:-./config.json} python3 -m wan_probe

image:
	docker build -t $(IMAGE):$(VERSION) .

chart-lint:
	helm lint charts/wan-probe

chart-template:
	helm template wan-probe charts/wan-probe --set image.tag=$(VERSION)
