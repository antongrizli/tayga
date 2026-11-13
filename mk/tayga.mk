# Tayga daemon and helper targets
SOURCES := src/experimental_io.c src/nat64.c src/addrmap.c src/dynamic.c src/tayga.c \
           src/conffile.c src/log.c src/tun.c src/gso.c src/stats.c src/stats_exporter.c

OBJS := $(patsubst src/%.c,$(OBJDIR)/%.o,$(SOURCES))

CPPFLAGS += -Isrc -I$(GENDIR)

.PHONY: FORCE
FORCE:

$(GENDIR)/version.h: FORCE | $(GENDIR)
	@mkdir -p $(GENDIR)
	@printf '#ifndef __TAYGA_VERSION_H__\n#define __TAYGA_VERSION_H__\n\n#define TAYGA_VERSION "%s"\n#define TAYGA_BRANCH  "%s"\n#define TAYGA_COMMIT  "%s"\n\n#endif /* #ifndef __TAYGA_VERSION_H__ */\n' \
		"$(VERSION)" "$(BRANCH)" "$(COMMIT)" > $(GENDIR)/version.h.tmp
	@if cmp -s $(GENDIR)/version.h.tmp $(GENDIR)/version.h 2>/dev/null; then \
		rm -f $(GENDIR)/version.h.tmp; \
	else \
		mv $(GENDIR)/version.h.tmp $(GENDIR)/version.h; \
	fi

$(BUILDDIR) $(GENDIR) $(OBJDIR) $(TESTOBJDIR) $(TESTBINDIR) $(SHIMDIR):
	@mkdir -p $@

$(OBJDIR)/%.o: src/%.c $(GENDIR)/version.h $(BUILDDIR)/build.flags | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

# Compile Tayga
$(BUILDDIR)/tayga: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

# Compile Tayga (statically link)
.PHONY: static
static: tayga

# Root-level symlink/copy for backward compatibility
tayga: $(BUILDDIR)/tayga
	@cp $(BUILDDIR)/tayga tayga

# Compile Tayga with big-endian s390x
taygabe: $(SOURCES) $(GENDIR)/version.h
	s390x-linux-gnu-gcc $(CPPFLAGS) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS) $(LDLIBS)

# Helper tools
PREF64_SOURCES := src/helpers/pref64-discover.c src/helpers/pref64_ra.c \
                  src/helpers/dns64_serve.c src/helpers/ra_supervisor.c src/helpers/tun_probe.c
PREF64_OBJS := $(patsubst src/%.c,$(OBJDIR)/%.o,$(PREF64_SOURCES))

# Static pattern rule: wins over $(OBJDIR)/%.o under GNU make 3.81 (macOS) too.
$(PREF64_OBJS): $(OBJDIR)/helpers/%.o: src/helpers/%.c $(GENDIR)/version.h $(BUILDDIR)/build.flags
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILDDIR)/pref64-discover: $(PREF64_OBJS) | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(PREF64_OBJS) $(LDFLAGS)

pref64-discover: $(BUILDDIR)/pref64-discover
	@cp $(BUILDDIR)/pref64-discover pref64-discover

$(BUILDDIR)/probe-tun-offload: tools/probe-tun-offload.c $(BUILDDIR)/build.flags | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: tools/probe-tun-offload
tools/probe-tun-offload: $(BUILDDIR)/probe-tun-offload
	@cp $< $@


# Compare before replacing so unchanged invocations remain incremental.
$(BUILDDIR)/build.flags: FORCE | $(BUILDDIR)
	@printf '%s\n' 'CC=$(CC)' 'CPPFLAGS=$(CPPFLAGS)' 'CFLAGS=$(CFLAGS)' 'LDFLAGS=$(LDFLAGS)' 'LDLIBS=$(LDLIBS)' 'AR=$(AR)' 'TEST_CFLAGS=$(TEST_CFLAGS)' 'TEST_LDFLAGS=$(TEST_LDFLAGS)' > $@.tmp
	@cmp -s $@.tmp $@ && rm -f $@.tmp || mv $@.tmp $@

-include $(OBJS:.o=.d) $(PREF64_OBJS:.o=.d)
