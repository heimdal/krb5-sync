AM_CFLAGS = -DSBINDIR=\"@sbindir@\" -DFOREIGNREALM=\"@FOREIGNREALM@\"

moduledir = $(prefix)/var/krb5kdc
module_LTLIBRARIES = pwupdate.la

pwupdate_la_SOURCES = kadmin_plugin.c 
pwupdate_la_LDFLAGS = -module -avoid-version
pwupdate_la_CFLAGS = $(AM_CFLAGS)
pwupdate_la_LIBADD = -lkrb5 -lk5crypto -lcom_err
