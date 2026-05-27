# shelob-ng / Juice Shop example runner
# Usage: make <target>
#
# Quick start:
#   make setup    — build fuzzer, start Juice Shop, create accounts
#   make run-1    — quick smoke test (5m, no auth)
#   make run-full — full 1-hour audit (all features)
#   make report   — summarise findings from all scenarios

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

# Allow overriding duration from command line: DURATION_QUICK=2m make run-1
export DURATION_QUICK  ?= 5m
export DURATION_STANDARD ?= 15m
export DURATION_FULL   ?= 1h
export RPS             ?= 0

SCRIPTS := ./scripts

.PHONY: help build check setup \
        start start-csp stop logs \
        run-1 run-2 run-3 run-4 run-5 run-6 run-7 run-8 \
        run-all run-quick report coverage-report clean

## help: print this message
help:
	@echo "shelob-ng / Juice Shop example targets:"
	@echo ""
	@echo "  Infrastructure:"
	@echo "    make check       — verify prerequisites (Go, Docker, curl)"
	@echo "    make build       — build the shelob-ng binary"
	@echo "    make start       — start Juice Shop (standard, port 3000)"
	@echo "    make start-csp   — start Juice Shop + CSP sidecar (ports 3000+8080)"
	@echo "    make stop        — stop all containers"
	@echo "    make logs        — tail Juice Shop container logs"
	@echo "    make setup       — full first-time setup (build + start + accounts + spec)"
	@echo ""
	@echo "  Scenarios (set DURATION_QUICK=2m for faster runs):"
	@echo "    make run-1       — Scenario 1: pure random (no auth)"
	@echo "    make run-2       — Scenario 2: authenticated"
	@echo "    make run-3       — Scenario 3: BOLA / NameSpaceRule (two users)"
	@echo "    make run-4       — Scenario 4: security payload injection"
	@echo "    make run-5       — Scenario 5: coverage-guided (CSP, needs start-csp)"
	@echo "    make run-6       — Scenario 6: corpus persistence (two runs)"
	@echo "    make run-7       — Scenario 7: selective checkers (3 sub-scenarios)"
	@echo "    make run-8       — Scenario 8: full (all features, $(DURATION_FULL))"
	@echo ""
	@echo "  Convenience:"
	@echo "    make run-quick        — scenarios 1-4 back-to-back (no CSP)"
	@echo "    make run-all          — all 8 scenarios (requires start-csp for run-5)"
	@echo "    make report           — summarise findings from all results/"
	@echo "    make coverage-report  — HTML coverage report via c8 (requires start-csp)"
	@echo "    make clean            — remove results/ and corpus/ directories"
	@echo ""
	@echo "  Override durations:"
	@echo "    DURATION_QUICK=2m DURATION_STANDARD=5m make run-quick"

## build: compile shelob-ng binary
build:
	cd .. && go build -o shelob-ng .
	@echo "Built: ../shelob-ng"

## check: verify prerequisites
check:
	@bash $(SCRIPTS)/00_check.sh

## setup: full first-time setup
setup: build
	@bash $(SCRIPTS)/01_setup.sh

## start: start standard Juice Shop (no CSP)
start:
	docker compose up -d
	@echo "Waiting for Juice Shop..."
	@for i in $$(seq 1 30); do \
		curl -s --connect-timeout 2 http://localhost:3000/rest/admin/application-configuration > /dev/null && \
		echo "Juice Shop ready at http://localhost:3000" && exit 0 || true; \
		sleep 3; \
	done; \
	echo "ERROR: Juice Shop did not start. Run: docker compose logs"

## start-csp: build and start CSP-instrumented Juice Shop
start-csp:
	docker compose -f docker-compose.yml -f docker-compose.csp.yml build
	docker compose -f docker-compose.yml -f docker-compose.csp.yml up -d
	@echo "Waiting for Juice Shop + CSP sidecar..."
	@for i in $$(seq 1 40); do \
		curl -s --connect-timeout 2 http://localhost:3000/rest/admin/application-configuration > /dev/null && \
		curl -s --connect-timeout 2 -X POST http://localhost:8080/csp/reset > /dev/null && \
		echo "Juice Shop + CSP ready (ports 3000, 8080)" && exit 0 || true; \
		sleep 3; \
	done; \
	echo "ERROR: startup timeout. Run: docker compose logs"

## stop: stop all containers
stop:
	-docker compose -f docker-compose.yml -f docker-compose.csp.yml down 2>/dev/null || true
	-docker compose down 2>/dev/null || true

## logs: tail Juice Shop logs
logs:
	docker compose logs -f

# -----------------------------------------------------------------------
# Scenarios
# -----------------------------------------------------------------------

## run-1: Scenario 1 — pure random mode
run-1:
	@bash $(SCRIPTS)/02_scenario_pure_random.sh

## run-2: Scenario 2 — authenticated
run-2:
	@bash $(SCRIPTS)/03_scenario_authenticated.sh

## run-3: Scenario 3 — BOLA detection
run-3:
	@bash $(SCRIPTS)/04_scenario_bola.sh

## run-4: Scenario 4 — security payload injection
run-4:
	@bash $(SCRIPTS)/05_scenario_payloads.sh

## run-5: Scenario 5 — coverage-guided (requires start-csp)
run-5:
	@bash $(SCRIPTS)/06_scenario_coverage.sh

## run-6: Scenario 6 — corpus persistence
run-6:
	@bash $(SCRIPTS)/07_scenario_corpus.sh

## run-7: Scenario 7 — selective checkers
run-7:
	@bash $(SCRIPTS)/08_scenario_checkers.sh

## run-8: Scenario 8 — full audit
run-8:
	@bash $(SCRIPTS)/09_scenario_full.sh

## run-quick: scenarios 1-4 back-to-back (no CSP required)
run-quick: run-1 run-2 run-3 run-4
	@echo "Quick run complete. Run 'make report' for summary."

## run-all: all 8 scenarios (run start-csp first for scenario 5)
run-all: run-1 run-2 run-3 run-4 run-5 run-6 run-7 run-8
	@$(MAKE) report

## report: summarise all findings
report:
	@bash $(SCRIPTS)/10_report.sh

## coverage-report: generate HTML coverage report from accumulated V8 data (requires start-csp)
coverage-report:
	@bash $(SCRIPTS)/11_coverage_report.sh

## clean: remove generated directories
clean:
	rm -rf results/ corpus/
	@echo "Cleaned: results/ corpus/"
