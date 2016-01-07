ACLOCAL_AMFLAGS = -I m4

internalcfg = $(DESTDIR)$(sysconfdir)/ipfixcol/internalcfg.xml
ipfixconf = $(DESTDIR)/$(exec_prefix)/bin/ipfixconf
pluginsdir = $(datadir)/ipfixcol/plugins
sofile = $(pluginsdir)/ipfixcol-httpfieldmerge-inter.so

AM_CPPFLAGS = -I$(top_srcdir)/headers

plugins_LTLIBRARIES = ipfixcol-httpfieldmerge-inter.la
ipfixcol_httpfieldmerge_inter_la_LDFLAGS = -module -avoid-version -shared
ipfixcol_httpfieldmerge_inter_la_LIBADD = -lrt

ipfixcol_httpfieldmerge_inter_la_SOURCES = fields.h pens.h field_mappings.h httpfieldmerge.h httpfieldmerge.c uthash.h vendor_proc/processors.h vendor_proc/processors.c vendor_proc/cisco.h vendor_proc/cisco.c vendor_proc/ntop.h vendor_proc/ntop.c vendor_proc/other.h vendor_proc/other.c

.PHONY: clean-local
clean-local:
	rm -rf RPMBUILD

.PHONY: install-data-hook
install-data-hook:
	@if [ -f "$(internalcfg)" ]; then \
		$(ipfixconf) add -c "$(internalcfg)" -p m -n httpfieldmerge -t httpfieldmerge -s "$(sofile)" -f; \
	fi

.PHONY: test
test:
	$(MAKE) $(ACLOCAL_AMFLAGS)
	(cd tests/ && ./test.sh) || exit 1

