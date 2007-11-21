# Makefile.am -- Automake makefile for krb5-sync.
# $Id$
#
# Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = autogen patches/README patches/mit-krb5-1.4.4 \
	patches/stanford-krb5-1.4.4 tools/krb5-sync.8 tools/krb5-sync.pod \
	tools/krb5-sync-backend.8

# Handle the standard stuff that make maintainer-clean should probably remove
# but doesn't.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
	configure tools/krb5-sync.8

# Put the module into /usr/local/lib/kadmind by default, relative to --libdir.
moduledir = $(libdir)/kadmind

# Rules for building the password synchronization plugin.
module_LTLIBRARIES = plugin/passwd_update.la
plugin_passwd_update_la_SOURCES = plugin/ad.c plugin/afs.c plugin/api.c \
	plugin/internal.h plugin/queue.c
plugin_passwd_update_la_LDFLAGS = -module -avoid-version

# Rules for building the krb5-sync utility.  We specify the CFLAGS to work
# around Automake's inability to link libtool objects into a program that
# isn't otherwise using libtool.  Per the Automake manual, specifying CFLAGS
# will cause the sources to be built twice, once with a prefix for this
# program.
sbin_PROGRAMS = tools/krb5-sync
tools_krb5_sync_SOURCES = util/krb5-sync.c $(plugin_passwd_update_la_SOURCES)
tools_krb5_sync_CFLAGS = $(AM_CFLAGS)

# Rules for the krb5-sync-backend script.
dist_sbin_SCRIPTS = tools/krb5-sync-backend

# Rules for man pages.
man_MANS = tools/krb5-sync.8 tools/krb5-sync-backend.8

$(srcdir)/tools/krb5-sync.8: $(srcdir)/tools/krb5-sync.pod
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/tools/krb5-sync.pod > $@

$(srcdir)/tools/krb5-sync-backend.8: $(srcdir)/tools/krb5-sync-backend
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/tools/krb5-sync-backend > $@

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wcast-align -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
