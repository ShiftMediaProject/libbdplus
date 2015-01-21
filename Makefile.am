ACLOCAL_AMFLAGS=-I m4

EXTRA_DIST=bootstrap COPYING README.txt

SET_FEATURES = @SET_FEATURES@
SET_INCLUDES = -I$(top_srcdir)/src -I$(top_builddir)/src/libbdplus

AM_CFLAGS = -std=c99 $(SET_FEATURES) $(SET_INCLUDES) $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)

lib_LTLIBRARIES = libbdplus.la
libbdplus_la_SOURCES=\
	src/libbdplus/bdplus.h \
	src/libbdplus/internal.c \
	src/libbdplus/bdplus.c \
	src/libbdplus/bdplus_data.h \
	src/libbdplus/internal.h \
	src/libbdplus/bdplus_config.c \
	src/libbdplus/bdplus_config.h \
	src/libbdplus/bdsvm/diff.h \
	src/libbdplus/bdsvm/event.c \
	src/libbdplus/bdsvm/event.h \
	src/libbdplus/bdsvm/loader.c \
	src/libbdplus/bdsvm/loader.h \
	src/libbdplus/bdsvm/segment.c \
	src/libbdplus/bdsvm/trap_helper.c \
	src/libbdplus/bdsvm/trap.c \
	src/libbdplus/bdsvm/slot.h \
	src/libbdplus/bdsvm/slot_data.h \
	src/libbdplus/bdsvm/segment.h \
	src/libbdplus/bdsvm/interface.h \
	src/libbdplus/bdsvm/dlx.c \
	src/libbdplus/bdsvm/interface.c \
	src/libbdplus/bdsvm/dlx.h \
	src/libbdplus/bdsvm/dlx_internal.h \
	src/libbdplus/bdsvm/diff.c \
	src/libbdplus/bdsvm/slot.c \
	src/libbdplus/bdsvm/trap.h \
	src/libbdplus/bdsvm/trap_helper.h \
	src/libbdplus/bdsvm/sha1.h \
	src/libbdplus/bdsvm/sha1.c \
	src/file/dirs.h \
	src/file/file.h \
	src/file/filesystem.h \
	src/file/file_default.c \
	src/file/file_default.h \
	src/file/configfile.c \
	src/file/configfile.h \
	src/util/attributes.h \
	src/util/macro.h \
	src/util/mutex.h \
	src/util/mutex.c \
	src/util/strutl.c \
	src/util/strutl.h \
	src/util/logging.c \
	src/util/logging.h

if HAVE_DARWIN
libbdplus_la_SOURCES+= \
	src/file/dirs_darwin.c
else
if HAVE_WIN32
libbdplus_la_SOURCES+= \
	src/file/dirs_win32.c
else
libbdplus_la_SOURCES+= \
	src/file/dirs_xdg.c
endif
endif

pkginclude_HEADERS = \
	src/libbdplus/bdplus.h \
	src/libbdplus/bdplus-version.h

libbdplus_la_LDFLAGS= -no-undefined -version-info $(LT_VERSION_INFO)
libbdplus_la_LIBADD = $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS)
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = src/libbdplus.pc


#
# examples
#

noinst_PROGRAMS = bdplus_test convtab_dump

bdplus_test_SOURCES = src/examples/bdplus_test.c
bdplus_test_CFLAGS  = $(AM_CFLAGS) $(LIBAACS_CFLAGS)
bdplus_test_LDADD   = libbdplus.la
bdplus_test_LDADD  += $(LIBAACS_LIBS)

convtab_dump_SOURCES = src/examples/convtab_dump.c
