# Automake makefile for krb5-sync.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2015 Russ Allbery <eagle@eyrie.org>
# Copyright 2006, 2007, 2010, 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore LICENSE autogen patches/README			    \
	patches/heimdal-1.3.1 tests/README tests/TESTS			    \
	tests/data/krb5-empty.conf tests/data/krb5.conf			    \
	tests/data/make-krb5-conf tests/data/perl.conf			    \
	tests/data/perlcriticrc tests/data/perltidyrc			    \
	tests/data/valgrind.supp tests/docs/pod-spelling-t tests/docs/pod-t \
	tests/perl/critic-t tests/perl/minimum-version-t		    \
	tests/perl/strict-t tests/tap/libtap.sh tests/tap/perl/Test/RRA.pm  \
	tests/tap/perl/Test/RRA/Automake.pm				    \
	tests/tap/perl/Test/RRA/Config.pm tests/tools/backend-t		    \
	tests/util/xmalloc-t tools/krb5-sync.pod

# Everything in the package needs to be able to find the Kerberos headers
# and libraries.
AM_CPPFLAGS = $(KRB5_CPPFLAGS)
AM_LDFLAGS = $(KRB5_LDFLAGS)

noinst_LTLIBRARIES = portable/libportable.la util/libutil.la
portable_libportable_la_SOURCES = portable/dummy.c portable/kadmin.h	\
	portable/krb5-extra.c portable/krb5.h portable/macros.h		\
	portable/stdbool.h portable/system.h
portable_libportable_la_LIBADD = $(LTLIBOBJS) $(KRB5_LIBS)
util_libutil_la_SOURCES = util/macros.h util/messages-krb5.c		    \
        util/messages-krb5.h util/messages.c util/messages.h util/xmalloc.c \
        util/xmalloc.h
util_libutil_la_LIBADD = portable/libportable.la $(KRB5_LIBS)

# Put the module into /usr/local/lib/krb5/plugins/kadm5_hook by default,
# relative to --libdir.
moduledir = $(libdir)/krb5/plugins/kadm5_hook

# Rules for building the krb5-sync plugin.
module_LTLIBRARIES = plugin/sync.la
plugin_sync_la_SOURCES = plugin/ad.c plugin/config.c plugin/error.c	\
	plugin/internal.h plugin/general.c plugin/heimdal.c		\
	plugin/instance.c plugin/logging.c plugin/mit.c plugin/queue.c	\
	plugin/vector.c
plugin_sync_la_CPPFLAGS = $(KADM5SRV_CPPFLAGS) $(LDAP_CPPFLAGS) \
	$(AM_CPPFLAGS)
plugin_sync_la_LDFLAGS = -module -avoid-version $(KADM5SRV_LDFLAGS) \
	$(LDAP_LDFLAGS) $(AM_LDFLAGS)
plugin_sync_la_LIBADD = portable/libportable.la $(KADM5SRV_LIBS) \
	$(LDAP_LIBS) $(KRB5_LIBS)

# Rules for building the krb5-sync utility.
sbin_PROGRAMS = tools/krb5-sync
tools_krb5_sync_SOURCES = tools/krb5-sync.c $(plugin_sync_la_SOURCES)
tools_krb5_sync_CPPFLAGS = $(KADM5SRV_CPPFLAGS) $(LDAP_CPPFLAGS) $(AM_CPPFLAGS)
tools_krb5_sync_LDFLAGS = $(KADM5SRV_LDFLAGS) $(LDAP_LDFLAGS) $(AM_LDFLAGS)
tools_krb5_sync_LDADD = portable/libportable.la util/libutil.la	\
	$(KADM5SRV_LIBS) $(LDAP_LIBS) $(KRB5_LIBS)

# Rules for the krb5-sync-backend script.
dist_sbin_SCRIPTS = tools/krb5-sync-backend

# Rules for man pages.
dist_man_MANS = tools/krb5-sync.8 tools/krb5-sync-backend.8

# Handle the standard stuff that make maintainer-clean should probably remove
# but doesn't.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/ar-lib		   \
	build-aux/compile build-aux/config.guess build-aux/config.sub	   \
	build-aux/depcomp build-aux/install-sh build-aux/ltmain.sh	   \
	build-aux/missing config.h.in config.h.in~ configure m4/libtool.m4 \
	m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4	   \
	tools/krb5-sync-backend.8 tools/krb5-sync.8

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on.  Desirable warnings that can't be turned
# on due to other problems:
#
#     -Wconversion      http://bugs.debian.org/488884 (htons warnings)
#
# Last checked against gcc 4.8.2 (2014-04-12).  -D_FORTIFY_SOURCE=2 enables
# warn_unused_result attribute markings on glibc functions on Linux, which
# catches a few more issues.
WARNINGS = -g -O -fstrict-overflow -fstrict-aliasing -D_FORTIFY_SOURCE=2   \
    -Wall -Wextra -Wendif-labels -Wformat=2 -Winit-self -Wswitch-enum	   \
    -Wstrict-overflow=5 -Wmissing-format-attribute -Wfloat-equal	   \
    -Wdeclaration-after-statement -Wshadow -Wpointer-arith		   \
    -Wbad-function-cast -Wcast-align -Wwrite-strings -Wjump-misses-init	   \
    -Wlogical-op -Wstrict-prototypes -Wold-style-definition		   \
    -Wmissing-prototypes -Wnormalized=nfc -Wpacked -Wredundant-decls	   \
    -Wnested-externs -Winline -Wvla -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/plugin/heimdal-t tests/plugin/mit-t   \
	tests/plugin/queue-only-t tests/plugin/queuing-t		    \
	tests/portable/asprintf-t tests/portable/mkstemp-t		    \
	tests/portable/reallocarray-t tests/portable/snprintf-t		    \
	tests/util/messages-krb5-t tests/util/messages-t tests/util/xmalloc
check_LIBRARIES = tests/tap/libtap.a
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests $(AM_CPPFLAGS)
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h	\
	tests/tap/kerberos.c tests/tap/kerberos.h tests/tap/macros.h	\
	tests/tap/messages.c tests/tap/messages.h tests/tap/process.c	\
	tests/tap/process.h tests/tap/string.c tests/tap/string.h	\
	tests/tap/sync.c tests/tap/sync.h

# All of the test programs.
tests_plugin_heimdal_t_LDADD = tests/tap/libtap.a portable/libportable.la \
	$(KRB5_LIBS) $(DL_LIBS)
tests_plugin_mit_t_LDADD = tests/tap/libtap.a portable/libportable.la \
	$(KRB5_LIBS) $(DL_LIBS)
tests_plugin_queue_only_t_SOURCES = tests/plugin/queue-only-t.c \
	$(plugin_sync_la_SOURCES)
tests_plugin_queue_only_t_CPPFLAGS = $(KADM5SRV_CPPFLAGS) $(LDAP_CPPFLAGS) \
	$(AM_CPPFLAGS)
tests_plugin_queue_only_t_LDFLAGS = $(KADM5SRV_LDFLAGS) $(LDAP_LDFLAGS) \
	$(AM_LDFLAGS)
tests_plugin_queue_only_t_LDADD = tests/tap/libtap.a portable/libportable.la \
	$(KADM5SRV_LIBS) $(LDAP_LIBS) $(KRB5_LIBS)
tests_plugin_queuing_t_SOURCES = tests/plugin/queuing-t.c \
	$(plugin_sync_la_SOURCES)
tests_plugin_queuing_t_CPPFLAGS = $(KADM5SRV_CPPFLAGS) $(LDAP_CPPFLAGS) \
	$(AM_CPPFLAGS)
tests_plugin_queuing_t_LDFLAGS = $(KADM5SRV_LDFLAGS) $(LDAP_LDFLAGS) \
	$(AM_LDFLAGS)
tests_plugin_queuing_t_LDADD = tests/tap/libtap.a portable/libportable.la \
	$(KADM5SRV_LIBS) $(LDAP_LIBS) $(KRB5_LIBS)
tests_portable_asprintf_t_SOURCES = tests/portable/asprintf-t.c \
	tests/portable/asprintf.c
tests_portable_asprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_mkstemp_t_SOURCES = tests/portable/mkstemp-t.c \
	tests/portable/mkstemp.c
tests_portable_mkstemp_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_reallocarray_t_SOURCES = tests/portable/reallocarray-t.c \
	tests/portable/reallocarray.c
tests_portable_reallocarray_t_LDADD = tests/tap/libtap.a \
	portable/libportable.la
tests_portable_snprintf_t_SOURCES = tests/portable/snprintf-t.c \
	tests/portable/snprintf.c
tests_portable_snprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_util_messages_krb5_t_LDADD = tests/tap/libtap.a util/libutil.la \
	portable/libportable.la $(KRB5_LIBS)
tests_util_messages_t_LDADD = tests/tap/libtap.a util/libutil.la \
	portable/libportable.la
tests_util_xmalloc_LDADD = util/libutil.la portable/libportable.la

check-local: $(check_PROGRAMS)
	cd tests && ./runtests -l $(abs_top_srcdir)/tests/TESTS

# Used by maintainers to run the main test suite under valgrind.  Suppress
# the xmalloc and pod-spelling tests because the former won't work properly
# under valgrind (due to increased memory usage) and the latter is pointless
# to run under valgrind.
check-valgrind: $(check_PROGRAMS)
	rm -rf $(abs_top_builddir)/tmp-valgrind
	mkdir $(abs_top_builddir)/tmp-valgrind
	env RRA_MAINTAINER_TESTS= valgrind --leak-check=full	\
	    --show-reachable=yes --trace-children=yes		\
	    --log-file=$(abs_top_builddir)/tmp-valgrind/log.%p	\
	    --suppressions=tests/data/valgrind.supp		\
	    --trace-children-skip="/bin/sh,*/cat,*/diff,*/expr,*/grep,*/mkdir,*/rm,*/rmdir,*/sed,*/sleep,*/true,*/wc,*/docs/*-t,*/perl/*-t,*/data/make-krb5-conf" \
	    tests/runtests -l '$(abs_top_srcdir)/tests/TESTS'
