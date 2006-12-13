# Makefile.am -- Top-level Automake makefile for krb5-passwd-sync.
# $Id$
#
# Copyright 2006 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = autogen

# Put the module into the KDC database directory for now.  This too needs to
# become configurable, this time in the patch.
moduledir = $(libdir)/kadmind

# Rules for building the password synchronization plugin.
module_LTLIBRARIES = plugin/passwd_update.la
plugin_passwd_update_la_SOURCES = plugin/ad.c plugin/afs.c plugin/api.c
plugin_passwd_update_la_LDFLAGS = -module -avoid-version

# Rules for building the ad-modify utility.
bin_PROGRAMS = util/ad-modify
util_ad_modify_SOURCES = util/ad-modify.c
util_ad_modify_LDADD = -lldap
