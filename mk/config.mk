# Configuration and compiler flags
TOPDIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/..)

# Default compiler flags
CC ?= gcc
CFLAGS ?= -Wall -O2
LDFLAGS ?= -flto=auto
LDLIBS := -lpthread

ifeq ($(WITH_URING),1)
override CFLAGS += -DTAYGA_WITH_URING
override LDFLAGS += -luring
endif

# Build directory
BUILDDIR ?= build
GENDIR := $(BUILDDIR)/gen
OBJDIR := $(BUILDDIR)/obj

# Installation paths
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

# Version determination (fallback: VERSION arg -> git describe -> VERSION file)
DEFAULT_VERSION := $(shell cat $(TOPDIR)/VERSION 2>/dev/null || echo "0.9.13")
VERSION ?= $(shell $(GIT) describe --tags --always --dirty 2>/dev/null || echo "$(DEFAULT_VERSION)")
ifeq ($(strip $(VERSION)),)
override VERSION := $(DEFAULT_VERSION)
endif
BRANCH  ?= $(shell $(GIT) rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
COMMIT  ?= $(shell $(GIT) rev-parse HEAD 2>/dev/null || echo "unknown")

# Link mode is part of the configuration even for combined static/helper goals.
ifneq ($(filter static,$(MAKECMDGOALS)),)
override LDFLAGS += -static
endif
AR ?= ar
TEST_CFLAGS ?= $(CFLAGS) -Werror
TEST_LDFLAGS ?= $(LDFLAGS)
ifeq ($(COVERAGE),1)
override TEST_CFLAGS += --coverage
override TEST_LDFLAGS += --coverage
endif
TESTOBJDIR := $(BUILDDIR)/test-obj
TESTBINDIR := $(BUILDDIR)/test-bin
TESTOUTDIR := $(BUILDDIR)/test-output
SHIMDIR := $(BUILDDIR)/shims

ifeq ($(strip $(BRANCH)),)
override BRANCH := unknown
endif
ifeq ($(strip $(COMMIT)),)
override COMMIT := unknown
endif
