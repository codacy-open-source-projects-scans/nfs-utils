## Process this file with automake to produce Makefile.in

noinst_LIBRARIES = 
noinst_LTLIBRARIES = libnfs.la libnfsconf.la

libnfs_la_SOURCES = exports.c rmtab.c xio.c rpcmisc.c rpcdispatch.c \
		   xcommon.c wildmat.c mydaemon.c \
		   rpc_socket.c getport.c \
		   svc_socket.c cacheio.c closeall.c nfs_mntent.c \
		   svc_create.c atomicio.c strlcat.c strlcpy.c ucred.c fh_key_file.c
libnfs_la_LIBADD = libnfsconf.la -luuid
libnfs_la_CPPFLAGS = $(AM_CPPFLAGS) $(CPPFLAGS) -I$(top_srcdir)/support/reexport

if CONFIG_NFSDCTL
libnfs_la_SOURCES += nfsdnl.c
libnfs_la_CPPFLAGS += $(LIBNL3_CFLAGS) $(LIBNLGENL3_CFLAGS) \
		      -I$(top_srcdir)/utils/nfsdctl
libnfs_la_LIBADD += $(LIBNL3_LIBS) $(LIBNLGENL3_LIBS)
endif

libnfsconf_la_SOURCES = conffile.c xlog.c

MAINTAINERCLEANFILES = Makefile.in

