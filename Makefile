# Main Makefile for TAYGA
.DEFAULT_GOAL := all
export PYTHONDONTWRITEBYTECODE := 1
include mk/config.mk
include mk/tayga.mk
include mk/test.mk
include mk/bench.mk
include mk/container.mk
include mk/install.mk

.PHONY: all
all: tayga

.PHONY: help
help:
	@echo 'Targets:'
	@echo 'all             - Compile tayga (produces build/tayga and ./tayga)'
	@echo 'static          - Compile tayga with static linkage'
	@echo 'test            - Run the C unit test suite'
	@echo 'test-portable   - Run portable non-root Python tests'
	@echo 'system-test     - Run Linux kernel acceptance tests (root)'
	@echo 'bench-tools     - Build benchmark helpers and fault shims'
	@echo 'integration     - Run integration tests (requires root/netns)'
	@echo 'release         - Bump VERSION, commit and create git tag'
	@echo 'man             - Generate man pages from markdown (requires pandoc)'
	@echo 'check-man       - Check that committed man pages match markdown sources'
	@echo 'check-docs      - Verify markdown documentation links'
	@echo 'install         - Installs tayga and manpages'
	@echo 'clean           - Remove compiled files and build artifacts'
	@echo
	@echo 'Compilation Variables:'
	@echo 'WITH_URING      - Compile with io_uring support (Linux only)'
	@echo 'WITH_BIG_ENDIAN - Run big-endian tests in integration suite'
	@echo
	@echo 'Installation Variables:'
	@echo 'LIVE            - Install on a live system (daemon-reload)'
	@echo 'WITH_SYSTEMD    - Install systemd scripts'
	@echo 'WITH_OPENRC     - Install OpenRC scripts and example config'

# Release preparation deliberately requires an explicit version and notes.
.PHONY: release
release:
	@test "$(origin VERSION)" = 'command line' && test -n "$(strip $(VERSION))" || { echo 'Use make release VERSION=x.y.z' >&2; exit 1; }
	python3 scripts/prepare-release.py "$(VERSION)"

RELEASE ?= $(DEFAULT_VERSION)
# Fixed metadata; update deliberately when publishing a release.
MAN_DATE ?= October 2026

.PHONY: man check-man
man:
	$(PANDOC) -s -t man -M footer="TAYGA $(RELEASE)" -M date="$(MAN_DATE)" docs/man/tayga.8.md -o docs/man/tayga.8
	$(PANDOC) -s -t man -M footer="TAYGA $(RELEASE)" -M date="$(MAN_DATE)" docs/man/tayga.conf.5.md -o docs/man/tayga.conf.5

check-man:
	@set -eu; task_man_dir=$$(mktemp -d); trap 'rm -rf "$$task_man_dir"' EXIT HUP INT TERM; \
	for page in tayga.8 tayga.conf.5; do \
	  $(PANDOC) -s -t man -M footer="TAYGA $(RELEASE)" -M date="$(MAN_DATE)" docs/man/$$page.md -o "$$task_man_dir/$$page"; \
	  diff -u docs/man/$$page "$$task_man_dir/$$page"; \
	done; echo 'Man pages are up to date.'

.PHONY: check-docs
check-docs:
	python3 scripts/ci/check-doc-links.py

.PHONY: update-scripts-version
update-scripts-version:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make update-scripts-version VERSION=<tag> [REPO=antongrizli/tayga]" >&2; exit 1; fi
	./scripts/update-image-tags.sh "$(VERSION)" "$(or $(REPO),antongrizli/tayga)" deploy/mikrotik

.PHONY: clean
clean:
	$(RM) -r $(BUILDDIR)
	$(RM) tayga taygabe pref64-discover tayga-nat64.tar tayga-clat.tar tayga.tar
	$(RM) $(UNIT_TESTS) unit_async_tun tools/probe-tun-offload tools/udp-drain-guard.so tools/udp-drain-control tools/iperf-start-gate.so tools/iperf-start-control *.gcda *.gcno
