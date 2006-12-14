# Makefile.am -- Top-level Automake makefile for krb5-passwd-sync.
# $Id$
#
# Copyright 2006 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = autogen

# Handle the standard stuff that make maintainer-clean should probably remove
# but doesn't.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
	configure

# Put the module into /usr/local/lib/kadmind by default, relative to --libdir.
moduledir = $(libdir)/kadmind

# Rules for building the password synchronization plugin.
module_LTLIBRARIES = plugin/passwd_update.la
plugin_passwd_update_la_SOURCES = plugin/ad.c plugin/afs.c plugin/api.c
plugin_passwd_update_la_LDFLAGS = -module -avoid-version

# Rules for building the ad-modify utility.
bin_PROGRAMS = util/ad-modify
util_ad_modify_SOURCES = util/ad-modify.c
util_ad_modify_LDADD = -lldap
