SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
SCRIPTS := ./scripts

export DURATION_QUICK    ?= 5m
export DURATION_STANDARD ?= 15m
export RPS               ?= 20

.PHONY: help build check setup start stop run-1 run-2 run-3 run-all clean

## help: print available targets
help:
	@echo "shelob-ng / VAmPI targets:"
	@echo "  make setup    — build fuzzer, start VAmPI, seed DB, fetch spec"
	@echo "  make start    — start VAmPI container"
	@echo "  make stop     — stop VAmPI container"
	@echo "  make run-1    — Scenario 1: basic authenticated scan"
	@echo "  make run-2    — Scenario 2: BOLA / NameSpaceRule (two users)"
	@echo "  make run-3    — Scenario 3: security payload injection"
	@echo "  make run-all  — all 3 scenarios"
	@echo "  make clean    — remove results/ and corpus/"
	@echo ""
	@echo "  Override: DURATION_QUICK=2m make run-1"

## build: compile shelob-ng binary
build:
	cd ../.. && go build -o shelob-ng .
	@echo "Built: ../../shelob-ng"

## setup: first-time setup
setup: build
	@bash $(SCRIPTS)/01_setup.sh

## start: start VAmPI container
start:
	docker compose up -d

## stop: stop VAmPI container
stop:
	docker compose down

## run-1: Scenario 1 — basic scan
run-1:
	@bash $(SCRIPTS)/02_scenario_basic.sh

## run-2: Scenario 2 — BOLA
run-2:
	@bash $(SCRIPTS)/03_scenario_bola.sh

## run-3: Scenario 3 — payloads
run-3:
	@bash $(SCRIPTS)/04_scenario_payloads.sh

## run-all: all 3 scenarios
run-all: run-1 run-2 run-3

## clean: remove generated directories
clean:
	rm -rf results/ corpus/
