# Makefile.am -- Top-level Automake makefile for krb5-passwd-sync.
# $Id$
#
# Copyright 2006 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
EXTRA_DIST = autogen

# This is a hack.  It needs to be runtime-configurable.
AM_CFLAGS = -DFOREIGNREALM=\"@FOREIGNREALM@\" -DAFSREALM=\"@AFSREALM@\"

# Put the module into the KDC database directory for now.  This too needs to
# become configurable, this time in the patch.
moduledir = $(prefix)/var/krb5kdc

# Rules for building the password synchronization plugin.
module_LTLIBRARIES = plugin/pwupdate.la
plugin_pwupdate_la_SOURCES = plugin/api.c plugin/k4.c
plugin_pwupdate_la_LDFLAGS = -module -avoid-version
plugin_pwupdate_la_LIBADD = -lkrb4 -lkrb5 -lk5crypto -lcom_err

# Rules for building the ad-modify utility.
bin_PROGRAMS = util/ad-modify
ad_modify_SOURCES = util/ad-modify.c
ad_modify_LIBADD = -lkrb5 -lldap
