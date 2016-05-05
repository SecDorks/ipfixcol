ACLOCAL_AMFLAGS = -I m4

internalcfg = $(DESTDIR)$(sysconfdir)/ipfixcol/internalcfg.xml
ipfixconf = $(DESTDIR)/$(exec_prefix)/bin/ipfixconf
pluginsdir = $(datadir)/ipfixcol/plugins
sofile = $(pluginsdir)/ipfixcol-timestampfieldmerge-inter.so

GIT_REV := $(shell git rev-parse HEAD)

AM_CPPFLAGS = -I$(top_srcdir)/headers -DGIT_REV=\"$(GIT_REV)\"

plugins_LTLIBRARIES = ipfixcol-timestampfieldmerge-inter.la
ipfixcol_timestampfieldmerge_inter_la_LDFLAGS = -module -avoid-version -shared
ipfixcol_timestampfieldmerge_inter_la_LIBADD = -lrt

ipfixcol_timestampfieldmerge_inter_la_SOURCES = timestampfieldmerge.h timestampfieldmerge.c uthash.h

.PHONY: clean-local
clean-local:
	rm -rf RPMBUILD

.PHONY: install-data-hook
install-data-hook:
	@if [ -f "$(internalcfg)" ]; then \
		$(ipfixconf) add -c "$(internalcfg)" -p m -n timestampfieldmerge -t timestampfieldmerge -s "$(sofile)" -f; \
	fi

.PHONY: test
test:
	$(MAKE) $(ACLOCAL_AMFLAGS)
	(cd tests/ && ./test.sh) || exit 1

