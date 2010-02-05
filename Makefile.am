# Automake makefile for krb5-sync.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006, 2007, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = LICENSE autogen patches/README patches/mit-krb5-1.4.4	\
	patches/stanford-krb5-1.4.4 tools/krb5-sync.pod

AM_CPPFLAGS = $(KRB5_CPPFLAGS)

noinst_LTLIBRARIES = portable/libportable.la
portable_libportable_la_SOURCES = portable/dummy.c portable/krb5-extra.c \
	portable/krb5.h portable/macros.h portable/stdbool.h		 \
	portable/system.h
portable_libportable_la_LDFLAGS = $(KRB5_LDFLAGS)
portable_libportable_la_LIBADD = $(LTLIBOBJS) $(KRB5_LIBS)

# Put the module into /usr/local/lib/kadmind by default, relative to --libdir.
moduledir = $(libdir)/kadmind

# Rules for building the password synchronization plugin.
module_LTLIBRARIES = plugin/passwd_update.la
plugin_passwd_update_la_SOURCES = plugin/ad.c plugin/api.c plugin/error.c \
	plugin/internal.h plugin/heimdal.c plugin/queue.c
plugin_passwd_update_la_LDFLAGS = -module -avoid-version $(KRB5_LDFLAGS)
plugin_passwd_update_la_LIBADD = portable/libportable.la $(KRB5_LIBS)

# Rules for building the krb5-sync utility.  We specify the CFLAGS to work
# around Automake's inability to link libtool objects into a program that
# isn't otherwise using libtool.  Per the Automake manual, specifying CFLAGS
# will cause the sources to be built twice, once with a prefix for this
# program.
sbin_PROGRAMS = tools/krb5-sync
tools_krb5_sync_SOURCES = tools/krb5-sync.c $(plugin_passwd_update_la_SOURCES)
tools_krb5_sync_CFLAGS = $(AM_CFLAGS)
tools_krb5_sync_LDFLAGS = $(KRB5_LDFLAGS)
tools_krb5_sync_LDADD = portable/libportable.la $(KRB5_LIBS)

# Rules for the krb5-sync-backend script.
dist_sbin_SCRIPTS = tools/krb5-sync-backend

# Rules for man pages.
dist_man_MANS = tools/krb5-sync.8 tools/krb5-sync-backend.8

# Handle the standard stuff that make maintainer-clean should probably remove
# but doesn't.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile		 \
	build-aux/config.guess build-aux/config.sub build-aux/depcomp	 \
	build-aux/install-sh build-aux/ltmain.sh build-aux/missing	 \
	config.h.in config.h.in~ configure m4/libtool.m4 m4/ltoptions.m4 \
	m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4			 \
	tools/krb5-sync-backend.8 tools/krb5-sync.8

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
