# Makefile.am -- Top-level Automake makefile for krb5-passwd-sync.
# $Id$
#
# Copyright 2006 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = autogen patches/README patches/mit-krb5-1.4.4 \
	util/krb5-sync.8 util/krb5-sync.pod

# Handle the standard stuff that make maintainer-clean should probably remove
# but doesn't.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
	configure util/krb5-sync.8

# Put the module into /usr/local/lib/kadmind by default, relative to --libdir.
moduledir = $(libdir)/kadmind

# Rules for building the password synchronization plugin.
module_LTLIBRARIES = plugin/passwd_update.la
plugin_passwd_update_la_SOURCES = plugin/ad.c plugin/afs.c plugin/api.c \
	plugin/internal.h
plugin_passwd_update_la_LDFLAGS = -module -avoid-version

# Rules for building the krb5-sync utility.  We specify the CFLAGS to work
# around Automake's inability to link libtool objects into a program that
# isn't otherwise using libtool.  Per the Automake manual, specifying CFLAGS
# will cause the sources to be built twice, once with a prefix for this
# program.
sbin_PROGRAMS = util/krb5-sync
util_krb5_sync_SOURCES = util/krb5-sync.c $(plugin_passwd_update_la_SOURCES)
util_krb5_sync_CFLAGS = $(AM_CFLAGS)

man_MANS = util/krb5-sync.8

$(srcdir)/util/krb5-sync.8: $(srcdir)/util/krb5-sync.pod
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/util/krb5-sync.pod > $@
