SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
SCRIPTS := ./scripts

export DURATION_QUICK    ?= 2m
export DURATION_STANDARD ?= 5m
export RPS               ?= 20

# Override to change where the RESTler repo is cloned
export DEMO_SRC ?= /opt/restler-fuzzer

.PHONY: help build setup stop run-1 clean

## help: print available targets
help:
	@echo "shelob-ng / RESTler Demo Server targets:"
	@echo "  make setup   — build fuzzer, clone RESTler, start demo server"
	@echo "  make stop    — kill background demo server process"
	@echo "  make run-1   — Scenario 1: producer-consumer dependency test"
	@echo "  make clean   — remove results/ and corpus/"
	@echo ""
	@echo "  Override clone location: DEMO_SRC=/tmp/restler make setup"

## build: compile shelob-ng binary
build:
	cd ../.. && go build -o shelob-ng .

## setup: install and start demo server
setup: build
	@bash $(SCRIPTS)/01_setup.sh

## stop: kill demo server
stop:
	@pkill -f "demo_server/app.py" 2>/dev/null && echo "Server stopped" || echo "Server not running"

## run-1: producer-consumer test
run-1:
	@bash $(SCRIPTS)/02_scenario_producer_consumer.sh

## clean: remove generated directories
clean:
	rm -rf results/ corpus/
