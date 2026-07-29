# =============================================================================
# Makefile — oracle_inject, the compiled AF_PACKET injector for the four-queue
# dequeue oracle.
#
# This Makefile NEVER runs sudo and never touches the switch. `make setcap`
# PRINTS the command you must run yourself; granting a capability is an operator
# decision, not a build step.
# =============================================================================
# make's built-in default for CC is `cc`, and `?=` would NOT override it (a
# default-origin variable counts as defined). Override only the built-in, so an
# explicit `make CC=clang` or an exported CC still wins.
ifeq ($(origin CC),default)
CC := gcc
endif

# Hard-set, not ?=, so an inherited CFLAGS cannot silently drop -Werror.
CFLAGS := -Wall -Wextra -Werror -O2 -std=c11 -D_GNU_SOURCE

BIN := oracle_inject
SRC := oracle_inject.c

# Absolute path of this directory, so the setcap hint is copy-pasteable from
# anywhere. $(MAKEFILE_LIST) is expanded before any recipe runs.
HERE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# A schedule small enough to eyeball, exercising all four roles.
CHECK_SCHEDULE := ablock:3,ack:1,rblock:3,resp:1

.PHONY: all clean setcap check

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BIN) *.o

# Prints the command. Does NOT run it, and does NOT run sudo.
setcap: $(BIN)
	@echo "# oracle_inject needs CAP_NET_RAW to open an AF_PACKET socket."
	@echo "# Run this yourself, once, on the injecting host:"
	@echo ""
	@echo "sudo setcap cap_net_raw+ep $(HERE)/$(BIN)"
	@echo ""
	@echo "# Verify with:   getcap $(HERE)/$(BIN)"
	@echo "# NOTE: rebuilding replaces the file and DROPS the capability."

# Dry-run smoke test: builds a plan, emits JSON, sends nothing, must exit 0.
# make aborts the recipe on a non-zero status, so reaching the echo IS the check.
check: $(BIN)
	./$(BIN) --dry-run --iface lo --trial-id 1 --schedule $(CHECK_SCHEDULE) --seed 1 > /dev/null
	@echo "check: --dry-run exited 0 (schedule $(CHECK_SCHEDULE))"
