# Makefile — runnable lab interface for the DNP3 timing-normalizer (directive §18).
#
# Offline-authored; the operator runs these against the live testbed. Every target
# forwards DRYRUN=1 as --dry-run so the whole flow can be reviewed without touching
# hardware:  make demo MODE=replay TRIALS=10 G_MS=25 DRYRUN=1
#
# Config comes from config/lab.env (falls back to config/lab.env.example). Overrides
# are passed as script FLAGS (which win over config), never as clobbering env.

SHELL       := /bin/bash
CONFIG      := $(if $(wildcard config/lab.env),config/lab.env,config/lab.env.example)
LOAD_ENV    := set -a; . $(CONFIG); set +a;
S           := ./scripts
PY          := python3
RPY         := $(shell $(LOAD_ENV) echo $${RESEARCH_PYTHON:-python3})

# ---- user-overridable knobs (passed as flags) ------------------------------
MODE        ?= replay
TRIALS      ?= 10
G_MS        ?= 25
K           ?=
RUNID       ?=
PCAP        ?=
OUTPUT      ?=
NATIVE_PREFIX ?=
PROTECTED_PREFIX ?=
DRYRUN      ?=

DRYFLAG     := $(if $(filter 1,$(DRYRUN)),--dry-run,)
KFLAG       := $(if $(K),--k $(K),)
RUNIDFLAG   := $(if $(RUNID),--runid $(RUNID),)

.DEFAULT_GOAL := help

.PHONY: help preflight build load configure-tm capture run-native run-protected \
        demo-native demo-protected analyze figures status restore demo clean-logs

help: ## show this help
	@echo "DNP3 timing-normalizer — lab interface (config: $(CONFIG))"
	@echo ""
	@echo "Preferred workflow:"
	@echo "  make preflight        # check the lab + show topology"
	@echo "  make build            # compile the P4 locally + verify sha/stages"
	@echo "  make load             # GUARDED bf_switchd swap to load the normalizer"
	@echo "  make configure-tm     # TM strict priority + clear Q_BLOCK shaper + set G"
	@echo "  make demo-native      # capture the un-normalized (native) interval"
	@echo "  make demo-protected   # capture the normalized (=G) interval"
	@echo "  make analyze PCAP=... # CLRT stats (tshark-gated)"
	@echo "  make figures          # render CLRT figures"
	@echo "  make restore          # return the switch to $(shell $(LOAD_ENV) echo $$SW_RESTORE_PROG)"
	@echo ""
	@echo "One-command guarded demo:"
	@echo "  make demo MODE=replay TRIALS=10 G_MS=25            # asks before changing the switch"
	@echo "  make demo MODE=replay TRIALS=10 G_MS=25 DRYRUN=1   # print remote cmds, touch nothing"
	@echo ""
	@echo "Meeting terminals (§23):  make status | make capture OUTPUT=x.pcap | make run-protected"
	@echo ""
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n",$$1,$$2}'

preflight: ## check reachability, Vision relay iface, one bf_switchd; show topology
	@$(LOAD_ENV) $(S)/00_preflight.sh $(DRYFLAG)

build: ## compile dnp3_timing_normalizer.p4 locally + verify sha/0-errors/stages
	@$(LOAD_ENV) $(S)/01_build.sh $(DRYFLAG)

load: ## GUARDED bf_switchd swap to load the timing program (asks to confirm)
	@$(LOAD_ENV) $(S)/02_load.sh $(DRYFLAG)

configure-tm: ## TM strict priority (C1/C2) + clear Q_BLOCK shaper (C3) + set G (D1)
	@$(LOAD_ENV) $(PY) $(S)/03_configure_tm.py --all --g-ms $(G_MS) $(DRYFLAG)

capture: ## passive full-frame capture until Ctrl+C: make capture OUTPUT=x.pcap
	@$(LOAD_ENV) $(S)/04_start_capture.sh --foreground $(if $(OUTPUT),--out $(OUTPUT),) $(RUNIDFLAG) $(DRYFLAG)

run-native: ## inject a native (bypass) replay trial + capture (MODE=live for real relay)
	@$(LOAD_ENV) MODE=$(MODE) $(S)/05_run_native.sh --trials $(TRIALS) $(RUNIDFLAG) $(DRYFLAG)

run-protected: ## inject a protected (hold_resp) replay trial + capture at G
	@$(LOAD_ENV) $(S)/06_run_protected.sh --trials $(TRIALS) --g-ms $(G_MS) $(KFLAG) $(RUNIDFLAG) $(DRYFLAG)

demo-native: run-native ## alias: native demo capture
demo-protected: run-protected ## alias: protected demo capture (then verify/analyze)

analyze: ## CLRT stats for a pcap (tshark-gated): make analyze PCAP=x.pcap [G_MS=25]
	@test -n "$(PCAP)" || { echo "usage: make analyze PCAP=<file.pcap> [G_MS=..]"; exit 2; }
	@$(LOAD_ENV) $(PY) $(S)/09_analyze_clrt.py --pcap $(PCAP) $(if $(G_MS),--g-ms $(G_MS),) $(DRYFLAG)

figures: ## render CLRT figures: make figures NATIVE_PREFIX=.. PROTECTED_PREFIX=..
	@$(LOAD_ENV) $(RPY) $(S)/10_generate_figures.py --g-ms $(G_MS) \
		$(if $(NATIVE_PREFIX),--native-prefix $(NATIVE_PREFIX),) \
		$(if $(PROTECTED_PREFIX),--protected-prefix $(PROTECTED_PREFIX),) $(DRYFLAG)

status: ## compact switch status for the meeting (§23)
	@$(LOAD_ENV) $(PY) $(S)/demo_status.py $(DRYFLAG)

restore: ## restore queue_microbench + verify lab health (idempotent, §26)
	@$(LOAD_ENV) $(S)/12_restore.sh $(DRYFLAG)

demo: ## the ONE guarded combined demo (§18): make demo MODE=replay TRIALS=10 G_MS=25
	@$(LOAD_ENV) $(S)/demo_all.sh --mode $(MODE) --trials $(TRIALS) --g-ms $(G_MS) $(DRYFLAG)

clean-logs: ## remove local logs (never touches evidence/)
	@rm -f logs/*.log 2>/dev/null; echo "logs cleared"
