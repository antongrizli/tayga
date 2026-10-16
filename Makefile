# Main Makefile for TAYGA
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

# Create a local release: update VERSION, commit and tag
.PHONY: release
release:
	@if [ -z "$(strip $(VERSION))" ]; then \
		echo "ERROR: Specify VERSION (e.g. make release VERSION=1.0.0)" >&2; \
		exit 1; \
	fi
	@RAW_VER="$(VERSION)"; \
	CLEAN_VER="$${RAW_VER#v}"; \
	CLEAN_VER="$${CLEAN_VER#version-}"; \
	CLEAN_VER="$${CLEAN_VER#version}"; \
	TAG="v$${CLEAN_VER}"; \
	echo "==> Preparing release $${TAG} (version $${CLEAN_VER})..."; \
	printf '%s\n' "$${CLEAN_VER}" > VERSION; \
	git add VERSION; \
	git commit -m "chore(release): $${TAG}"; \
	git tag -a "$${TAG}" -m "Release $${TAG}"; \
	echo "============================================================"; \
	echo "  Release $${TAG} created locally!"; \
	echo "  To publish to GitHub, run:"; \
	echo "    git push origin main --tags"; \
	echo "============================================================"

# Man pages
RELEASE ?= $(shell cat VERSION 2>/dev/null || echo "dev")
MAN_DATE ?= $(shell date '+%B %Y')

.PHONY: man
man:
	$(PANDOC) -s -t man -M footer="TAYGA $(RELEASE)" -M date="$(MAN_DATE)" docs/man/tayga.8.md -o docs/man/tayga.8
	$(PANDOC) -s -t man -M footer="TAYGA $(RELEASE)" -M date="$(MAN_DATE)" docs/man/tayga.conf.5.md -o docs/man/tayga.conf.5

.PHONY: check-man
check-man:
	@TMPDIR=$$(mktemp -d); \
	$(PANDOC) -s -t man -M footer="TAYGA $(RELEASE)" -M date="$(MAN_DATE)" docs/man/tayga.8.md -o $$TMPDIR/tayga.8; \
	$(PANDOC) -s -t man -M footer="TAYGA $(RELEASE)" -M date="$(MAN_DATE)" docs/man/tayga.conf.5.md -o $$TMPDIR/tayga.conf.5; \
	diff -u docs/man/tayga.8 $$TMPDIR/tayga.8 || (echo "docs/man/tayga.8 is out of date; run 'make man'" && rm -rf $$TMPDIR && exit 1); \
	diff -u docs/man/tayga.conf.5 $$TMPDIR/tayga.conf.5 || (echo "docs/man/tayga.conf.5 is out of date; run 'make man'" && rm -rf $$TMPDIR && exit 1); \
	rm -rf $$TMPDIR; \
	echo "Man pages are up to date."

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
