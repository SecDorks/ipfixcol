ACLOCAL_AMFLAGS = -I m4

internalcfg = $(DESTDIR)$(sysconfdir)/ipfixcol/internalcfg.xml
ipfixconf = $(DESTDIR)/$(exec_prefix)/bin/ipfixconf
pluginsdir = $(datadir)/ipfixcol/plugins
sofile = $(pluginsdir)/ipfixcol-proxy-inter.so

AM_CPPFLAGS = -I$(top_srcdir)/headers

plugins_LTLIBRARIES = ipfixcol-proxy-inter.la
ipfixcol_proxy_inter_la_LDFLAGS = -module -avoid-version -shared
ipfixcol_proxy_inter_la_LIBADD = -lrt

ipfixcol_proxy_inter_la_SOURCES = ares_util.c proxy_stat_thread.c proxy.c

.PHONY: clean-local
clean-local:
	rm -rf RPMBUILD

.PHONY: install-data-hook
install-data-hook:
	@if [ -f "$(internalcfg)" ]; then \
		$(ipfixconf) add -c "$(internalcfg)" -p m -n proxy -t proxy -s "$(sofile)" -f; \
	fi

