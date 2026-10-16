# Installation targets
.PHONY: install
install: tayga
	-mkdir -p $(DESTDIR)$(sbindir) $(DESTDIR)$(man5dir) $(DESTDIR)$(man8dir)
	$(INSTALL_PROGRAM) $(BUILDDIR)/tayga $(DESTDIR)$(sbindir)/tayga
	test -f docs/man/tayga.conf.5 && $(INSTALL_DATA) docs/man/tayga.conf.5 $(DESTDIR)$(man5dir) || true
	test -f docs/man/tayga.8 && $(INSTALL_DATA) docs/man/tayga.8 $(DESTDIR)$(man8dir) || true
ifdef WITH_SYSTEMD
	-mkdir -p $(DESTDIR)$(servicedir) $(DESTDIR)$(sysconfdir)/tayga
	$(INSTALL_DATA) packaging/systemd/tayga@.service $(DESTDIR)$(servicedir)/tayga@.service
	test -e $(DESTDIR)$(sysconfdir)/tayga/default.conf || $(INSTALL_DATA) packaging/tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga/default.conf
ifdef LIVE
	if test -d "/run/systemd/system" && test -x "$(SYSTEMCTL)"; then $(SYSTEMCTL) daemon-reload; fi
else
	@echo "Run 'systemctl daemon-reload' to have systemd recognize the newly installed service"
endif
	@echo "Systemd service installed. To enable: systemctl enable tayga@default.service"
endif
ifdef WITH_OPENRC
	@echo "Installing OpenRC unit and configurations"
	-mkdir -p $(DESTDIR)$(sysconfdir)/init.d $(DESTDIR)$(sysconfdir)/conf.d
	$(INSTALL_PROGRAM) packaging/openrc/tayga.initd $(DESTDIR)$(sysconfdir)/init.d/tayga
	$(INSTALL_DATA) packaging/openrc/tayga.confd $(DESTDIR)$(sysconfdir)/conf.d/tayga
	test -e $(DESTDIR)$(sysconfdir)/tayga.conf || $(INSTALL_DATA) packaging/tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga.conf
endif
