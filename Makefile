TOPDIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

# Default compiler flags
CC ?= gcc
CFLAGS ?= -Wall -O2
LDFLAGS ?= -flto=auto
LDLIBS := -lpthread
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c log.c tun.c gso.c stats.c stats_exporter.c

#Default installation paths (may be overridden by environment variables)
prefix ?= /usr/local
exec_prefix ?= $(prefix)
sbindir ?= $(exec_prefix)/sbin
datarootdir ?= $(prefix)/share
mandir ?= $(datarootdir)/man
man5dir ?= $(mandir)/man5
man8dir ?= $(mandir)/man8
sysconfdir ?= /etc
servicedir ?= $(sysconfdir)/systemd/system
DESTDIR ?=

# External programs
GIT ?= git
INSTALL ?= install
IP ?= ip
SYSTEMCTL ?= /bin/systemctl
PANDOC ?= pandoc

INSTALL_DATA ?= $(INSTALL) -m 644
INSTALL_PROGRAM ?= $(INSTALL)

.PHONY: all
all: tayga

.PHONY: help
help:
	@echo 'Targets:'
	@echo 'all             - Compile tayga (produces ./tayga)'
	@echo 'static          - Compile tayga with static linkage (produces ./tayga)'
	@echo 'test            - Run the test suite'
	@echo 'release         - Bump version.h, commit and create git tag (e.g. make release VERSION=1.0.0)'
	@echo 'integration     - Run integration tests. Requires root permissions'
	@echo 'man             - Generate man pages from markdown (requires pandoc)'
	@echo 'install         - Installs tayga and manpages'
	@echo 'clean           - Remove compiled files'
	@echo
	@echo 'Compilation Variables:'
	@echo 'WITH_EBPF	    - Compile with eBPF support (Linux only)'
	@echo 'WITH_MULTIQUEUE  - Compile with multi-queue support (Linux only)'
	@echo 'WITH_SEG_OFFLOAD - Compile with segmentation offload support (Linux only)'
	@echo 'WITH_URING       - Compile with io_uring support (Linux only)'
#TBD which optimizations we will support on BSD
	@echo
	@echo 'Installation Variables:'
	@echo 'LIVE            - Install on a live system (daemon-reload)'
	@echo 'WITH_SYSTEMD    - Install systemd scripts'
	@echo 'WITH_OPENRC     - Install OpenRC scripts and example config'

# Create a local release: update version.h, commit and tag
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
	printf '#ifndef __TAYGA_VERSION_H__\n#define __TAYGA_VERSION_H__\n\n#define TAYGA_VERSION "%s"\n#define TAYGA_BRANCH  "%s"\n#define TAYGA_COMMIT  "RELEASE"\n\n#endif /* #ifndef __TAYGA_VERSION_H__ */\n' \
		"$${CLEAN_VER}" "$${TAG}" > version.h; \
	git add version.h; \
	git commit -m "chore(release): $${TAG}"; \
	git tag -a "$${TAG}" -m "Release $${TAG}"; \
	echo "============================================================"; \
	echo "  Release $${TAG} created locally!"; \
	echo "  To publish to GitHub, run:"; \
	echo "    git push origin main --tags"; \
	echo "============================================================"

# Version determination (can be overridden via make VERSION=1.0.0 COMMIT=... BRANCH=...)
VERSION ?= $(shell $(GIT) describe --tags --always --dirty 2>/dev/null)
BRANCH  ?= $(shell $(GIT) rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
COMMIT  ?= $(shell $(GIT) rev-parse HEAD 2>/dev/null || echo "unknown")

# Synthesize the version.h header
define VERSION_HEADER
#ifndef __TAYGA_VERSION_H__
#define __TAYGA_VERSION_H__

#define TAYGA_VERSION "$(VERSION)"
#define TAYGA_BRANCH  "$(BRANCH)"
#define TAYGA_COMMIT  "$(COMMIT)"

#endif /* #ifndef __TAYGA_VERSION_H__ */
endef

.PHONY: version.h FORCE
version.h: FORCE
	@printf '#ifndef __TAYGA_VERSION_H__\n#define __TAYGA_VERSION_H__\n\n#define TAYGA_VERSION "%s"\n#define TAYGA_BRANCH  "%s"\n#define TAYGA_COMMIT  "%s"\n\n#endif /* #ifndef __TAYGA_VERSION_H__ */\n' \
		"$(VERSION)" "$(BRANCH)" "$(COMMIT)" > version.h

# Compile Tayga
tayga: $(SOURCES) version.h
	$(CC) $(CFLAGS) -o tayga $(SOURCES) $(LDFLAGS) $(LDLIBS)

# Compile Tayga (statically link)
.PHONY: static
static: LDFLAGS += -static
static: tayga

# Compile Tayga with big-endian s390x for big-endian checksum test cases
# S390x was chosen as it is officially supported by Debian and is Big-Endian
taygabe: $(SOURCES)
	$(eval $(make-version-header))
	s390x-linux-gnu-gcc $(CFLAGS) -o taygabe $(SOURCES) $(LDFLAGS) $(LDLIBS)

# Test suite compiles with -Werror to detect compiler warnings
.PHONY: test
test: unit_conffile unit_checksum unit_ip4_id unit_tun unit_gso unit_pref64 unit_stats
	./unit_conffile
	./unit_checksum
	./unit_ip4_id
	./unit_tun
	./unit_gso
	./unit_pref64
	./unit_stats

# these are only valid for GCC
TEST_CFLAGS := $(CFLAGS) -Werror -coverage -DCOVERAGE_TESTING
ifeq ($(CC),gcc)
TEST_CFLAGS += -coverage
endif
TEST_FILES := test/unit.c
unit_conffile: $(TEST_FILES) test/unit_conffile.c conffile.c addrmap.c tayga.h list.h
	$(CC) $(TEST_CFLAGS) -I. -o unit_conffile $(TEST_FILES) test/unit_conffile.c conffile.c addrmap.c $(LDFLAGS)

unit_checksum: test/unit_checksum.c tayga.h
	$(CC) $(CFLAGS) -I. -o unit_checksum test/unit_checksum.c $(LDFLAGS)

unit_ip4_id: test/unit_ip4_id.c nat64.c addrmap.c dynamic.c gso.c tun.c log.c stats.c tayga.h gso.h stats.h
	$(CC) $(CFLAGS) -I. -pthread -o unit_ip4_id test/unit_ip4_id.c nat64.c addrmap.c dynamic.c gso.c tun.c log.c stats.c $(LDFLAGS) -lpthread

unit_tun: test/unit_tun.c tun.c log.c stats.c tayga.h stats.h
	$(CC) $(CFLAGS) -I. -pthread -o unit_tun test/unit_tun.c tun.c log.c stats.c -Wl,--wrap=write -Wl,--wrap=writev $(LDFLAGS) -lpthread

unit_gso: test/unit_gso.c gso.c addrmap.c dynamic.c nat64.c tun.c log.c stats.c tayga.h gso.h stats.h
	$(CC) $(CFLAGS) -I. -pthread -o unit_gso test/unit_gso.c gso.c addrmap.c dynamic.c nat64.c tun.c log.c stats.c $(LDFLAGS) -lpthread

unit_pref64: test/unit_pref64.c src-helper/pref64-discover.c
	$(CC) $(CFLAGS) -DPREF64_NO_MAIN -I. -o unit_pref64 test/unit_pref64.c src-helper/pref64-discover.c $(LDFLAGS)

unit_stats: test/unit_stats.c stats.c stats_exporter.c log.c tayga.h stats.h
	$(CC) $(CFLAGS) -I. -pthread -o unit_stats test/unit_stats.c stats.c stats_exporter.c log.c $(LDFLAGS) -lpthread

pref64-discover: src-helper/pref64-discover.c
	$(CC) $(CFLAGS) -I. -o pref64-discover src-helper/pref64-discover.c $(LDFLAGS)

tools/probe-tun-offload: tools/probe-tun-offload.c
	$(CC) $(CFLAGS) -o tools/probe-tun-offload tools/probe-tun-offload.c

.PHONY: integration
integration: tayga
	-$(IP) netns add tayga-test
	$(IP) netns exec tayga-test python3 test/mapfile.py
	$(IP) netns exec tayga-test python3 test/addressing.py
	$(IP) netns exec tayga-test python3 test/mapping.py
	$(IP) netns exec tayga-test python3 test/translate.py
	$(IP) netns exec tayga-test python3 test/segment.py
# Do not run big-endian tests by default
ifdef WITH_BIG_ENDIAN
	$(IP) netns exec tayga-test python3 test/bigendian.py
endif
	$(IP) netns del tayga-test

# Generate man pages from markdown sources (requires pandoc)
# RELEASE comes from the release file generated by CI, or can be set manually
RELEASE ?= $(shell cat release 2>/dev/null || echo "dev")
MAN_DATE ?= $(shell date '+%B %Y')

.PHONY: man
man:
	$(PANDOC) -s -t man -M footer="TAYGA $(RELEASE)" -M date="$(MAN_DATE)" docs/man/tayga.8.md -o tayga.8
	$(PANDOC) -s -t man -M footer="TAYGA $(RELEASE)" -M date="$(MAN_DATE)" docs/man/tayga.conf.5.md -o tayga.conf.5

.PHONY: clean
clean:
	$(RM) tayga taygabe tayga-nat64.tar tayga-clat.tar tayga.tar pref64-discover
	$(RM) unit_conffile unit_checksum unit_ip4_id unit_tun unit_gso unit_pref64 unit_stats tools/probe-tun-offload *.gcda *.gcno

# Install tayga and man pages
.PHONY: install
install: $(TARGET)
	-mkdir -p $(DESTDIR)$(sbindir) $(DESTDIR)$(man5dir) $(DESTDIR)$(man8dir)
	$(INSTALL_PROGRAM) tayga $(DESTDIR)$(sbindir)/tayga
	$(INSTALL_DATA) tayga.conf.5 $(DESTDIR)$(man5dir)
	$(INSTALL_DATA) tayga.8 $(DESTDIR)$(man8dir)
# Install systemd service file
ifdef WITH_SYSTEMD
	-mkdir -p $(DESTDIR)$(servicedir) $(DESTDIR)$(sysconfdir)/tayga
	$(INSTALL_DATA) scripts/tayga@.service $(DESTDIR)$(servicedir)/tayga@.service
	test -e $(DESTDIR)$(sysconfdir)/tayga/default.conf || $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga/default.conf
ifdef LIVE
	if test -d "/run/systemd/system" && test -x "$(SYSTEMCTL)"; then $(SYSTEMCTL) daemon-reload; fi
else
	@echo "Run 'systemctl daemon-reload' to have systemd recognize the newly installed service"
endif
	@echo "Systemd service installed. To enable: systemctl enable tayga@default.service"
endif
# Install openrc init script
ifdef WITH_OPENRC
	@echo "Installing OpenRC unit and configurations"
	-mkdir -p $(DESTDIR)$(sysconfdir)/init.d $(DESTDIR)$(sysconfdir)/conf.d
	$(INSTALL_PROGRAM) scripts/tayga.initd $(DESTDIR)$(sysconfdir)/init.d/tayga
	$(INSTALL_DATA) scripts/tayga.confd $(DESTDIR)$(sysconfdir)/conf.d/tayga
	test -e $(DESTDIR)$(sysconfdir)/tayga.conf || $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga.conf
endif


# Container images
# As these are multi-arch containers,
# the build env requires qemu-user-static
# These are not listed in help as they are intended
# only for use by the build github actions
container: tayga-clat.tar tayga-nat64.tar tayga.tar
.PHONY: container

# Flags for Podman
PODMAN_FLAGS := --cgroup-manager=cgroupfs
ifdef CONT_ALL
#Option to build for all platforms
PODMAN_FLAGS += --all-platforms
endif

tayga.tar: scripts/launch.sh
	$(RM) $@
	podman manifest create tayga
	podman build $(PODMAN_FLAGS) . --manifest tayga
ifdef CONT_PUSH
	podman manifest push --all tayga ghcr.io/antongrizli/tayga:latest
endif
	podman save -o $@ tayga


tayga-clat.tar: scripts/launch-clat.sh
	$(RM) $@
	podman manifest create tayga-clat
	podman build $(PODMAN_FLAGS) . --manifest tayga-clat --target final-clat
ifdef CONT_PUSH
	podman manifest push --all tayga-clat ghcr.io/antongrizli/tayga-clat:latest
endif
	podman save -o $@ tayga-clat
	podman manifest rm tayga-clat

tayga-nat64.tar: scripts/launch-nat64.sh
	$(RM) $@
	podman manifest create tayga-nat64
	podman build $(PODMAN_FLAGS) . --manifest tayga-nat64 --target final-nat64
ifdef CONT_PUSH
	podman manifest push --all tayga-nat64 ghcr.io/antongrizli/tayga-nat64:latest
endif
	podman save -o $@ tayga-nat64
	podman manifest rm tayga-nat64