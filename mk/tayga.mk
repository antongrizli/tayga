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

$(GENDIR) $(OBJDIR):
	@mkdir -p $@

$(OBJDIR)/%.o: src/%.c $(GENDIR)/version.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

# Compile Tayga
$(BUILDDIR)/tayga: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

# Compile Tayga (statically link)
.PHONY: static
static: LDFLAGS += -static
static: tayga

# Root-level symlink/copy for backward compatibility
tayga: $(BUILDDIR)/tayga
	@cp $(BUILDDIR)/tayga tayga

# Compile Tayga with big-endian s390x
taygabe: $(SOURCES) $(GENDIR)/version.h
	s390x-linux-gnu-gcc $(CPPFLAGS) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS) $(LDLIBS)

# Helper tools
$(BUILDDIR)/pref64-discover: src/helpers/pref64-discover.c | $(BUILDDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc -o $@ $< $(LDFLAGS)

pref64-discover: $(BUILDDIR)/pref64-discover
	@cp $(BUILDDIR)/pref64-discover pref64-discover

tools/probe-tun-offload: tools/probe-tun-offload.c
	$(CC) $(CFLAGS) -o $@ $<
