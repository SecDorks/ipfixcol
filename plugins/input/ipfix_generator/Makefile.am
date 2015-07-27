ACLOCAL_AMFLAGS = -I m4

pluginsdir = $(datadir)/ipfixcol/plugins
internalcfg = $(DESTDIR)$(sysconfdir)/ipfixcol/internalcfg.xml
sofile = $(pluginsdir)/ipfixcol-ipfixgenerator-input.so

AM_CPPFLAGS = -I$(top_srcdir)/headers

plugins_LTLIBRARIES = ipfixcol-ipfixgenerator-input.la
ipfixcol_ipfixgenerator_input_la_LDFLAGS = -module -avoid-version -shared
ipfixcol_ipfixgenerator_input_la_LIBADD = -lrt

ipfixcol_ipfixgenerator_input_la_SOURCES = ipfixgenerator.c

.PHONY: clean-local
clean-local:
	rm -rf RPMBUILD

.PHONY: install-data-hook
install-data-hook:
	@if [ -f "$(internalcfg)" ]; then \
		ipfixconf add -c "$(internalcfg)" -p m -n ipfixgenerator -t ipfixgenerator -s "$(sofile)" -f; \
	fi

.PHONY: test
test:
	$(MAKE) $(ACLOCAL_AMFLAGS)
	(cd tests/ && ./test.sh) || exit 1

