ACLOCAL_AMFLAGS = -I m4

pluginsdir = $(pkgdatadir)/plugins
internalcfg = $(DESTIDR)$(sysconfdir)/ipfixcol/internalcfg.xml
sofile = $(pluginsdir)/ipfixcol-proxy-inter.so

AM_CPPFLAGS = -I$(top_srcdir)/headers

plugins_LTLIBRARIES = ipfixcol-httpfieldmerge-inter.la
ipfixcol_httpfieldmerge_inter_la_LDFLAGS = -module -avoid-version -shared
ipfixcol_httpfieldmerge_inter_la_LIBADD = -lrt

ipfixcol_httpfieldmerge_inter_la_SOURCES = httpfieldmerge.h httpfieldmerge.c uthash.h

clean-local:
	rm -rf RPMBUILD

install-data-hook:
	@if [ -f "$(internalcfg)" ]; then \
		ipfixconf add -c "$(internalcfg)" -p m -n httpfieldmerge -t httpfieldmerge -s "$(sofile)" -f; \
	fi

