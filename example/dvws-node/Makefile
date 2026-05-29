SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
SCRIPTS := ./scripts

export DURATION_QUICK    ?= 5m
export DURATION_STANDARD ?= 15m
export RPS               ?= 10

.PHONY: help build setup run-1 run-2 run-all clean

## help: print available targets
help:
	@echo "shelob-ng / DVWS-Node targets:"
	@echo "  make setup    — build fuzzer, verify DVWS is running, fetch spec"
	@echo "  make run-1    — Scenario 1: basic scan (all checkers)"
	@echo "  make run-2    — Scenario 2: injection payloads (SQLi/NoSQL/cmdi)"
	@echo "  make run-all  — all 2 scenarios"
	@echo "  make clean    — remove results/ and corpus/"
	@echo ""
	@echo "  External setup required:"
	@echo "    git clone https://github.com/snoopysecurity/dvws-node.git /opt/dvws-node"
	@echo "    cd /opt/dvws-node && docker-compose up -d"

## build: compile shelob-ng binary
build:
	cd ../.. && go build -o shelob-ng .

## setup: verify DVWS and fetch spec
setup: build
	@bash $(SCRIPTS)/01_setup.sh

## run-1: basic scan
run-1:
	@bash $(SCRIPTS)/02_scenario_basic.sh

## run-2: injection payloads
run-2:
	@bash $(SCRIPTS)/03_scenario_injection.sh

## run-all: all scenarios
run-all: run-1 run-2

## clean: remove generated directories
clean:
	rm -rf results/ corpus/
