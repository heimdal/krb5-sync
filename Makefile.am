# Makefile.am -- Top-level Automake makefile for krb5-passwd-sync.
# $Id$
#
# Copyright 2006 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = autogen

# This is a hack.  It needs to be runtime-configurable.
AM_CFLAGS = -DFOREIGNREALM=\"@FOREIGNREALM@\" -DAFSREALM=\"@AFSREALM@\"

# Put the module into the KDC database directory for now.  This too needs to
# become configurable, this time in the patch.
moduledir = $(libdir)/kadmind

# Rules for building the password synchronization plugin.
module_LTLIBRARIES = plugin/passwd_update.la
plugin_passwd_update_la_SOURCES = plugin/api.c plugin/k4.c
plugin_passwd_update_la_LDFLAGS = -module -avoid-version

# Rules for building the ad-modify utility.
bin_PROGRAMS = util/ad-modify
ad_modify_SOURCES = util/ad-modify.c
ad_modify_LIBADD = -lldap
