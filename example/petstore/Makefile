SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
SCRIPTS := ./scripts

export DURATION_QUICK ?= 5m
export RPS            ?= 10

.PHONY: help build setup start stop run-1 clean

## help: print available targets
help:
	@echo "shelob-ng / Swagger Petstore 3 targets:"
	@echo "  make setup    — build fuzzer, start Petstore, fetch spec"
	@echo "  make start    — start Petstore container"
	@echo "  make stop     — stop Petstore container"
	@echo "  make run-1    — Scenario 1: spec coverage baseline (apiKey auth)"
	@echo "  make clean    — remove results/ and corpus/"

## build: compile shelob-ng binary
build:
	cd ../.. && go build -o shelob-ng .

## setup: first-time setup
setup: build
	@bash $(SCRIPTS)/01_setup.sh

## start: start Petstore container
start:
	docker compose up -d

## stop: stop Petstore container
stop:
	docker compose down

## run-1: spec coverage baseline
run-1:
	@bash $(SCRIPTS)/02_scenario_coverage.sh

## clean: remove generated directories
clean:
	rm -rf results/ corpus/
