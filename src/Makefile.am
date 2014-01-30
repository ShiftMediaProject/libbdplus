SET_FEATURES = @SET_FEATURES@
SET_INCLUDES = -I$(top_srcdir) -Ilibbdplus

AM_CFLAGS = -std=c99 $(SET_FEATURES) $(SET_INCLUDES) $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)

lib_LTLIBRARIES = libbdplus.la
libbdplus_la_SOURCES=\
	libbdplus/bdplus.h \
	libbdplus/internal.c \
	libbdplus/bdplus.c \
	libbdplus/bdplus_data.h \
	libbdplus/internal.h \
	libbdplus/loader.c \
	libbdplus/loader.h \
	libbdplus/bdplus_config.c \
	libbdplus/bdplus_config.h \
	libbdplus/bdsvm/diff.h \
	libbdplus/bdsvm/event.c \
	libbdplus/bdsvm/event.h \
	libbdplus/bdsvm/segment.c \
	libbdplus/bdsvm/trap_helper.c \
	libbdplus/bdsvm/trap.c \
	libbdplus/bdsvm/slot.h \
	libbdplus/bdsvm/slot_data.h \
	libbdplus/bdsvm/segment.h \
	libbdplus/bdsvm/interface.h \
	libbdplus/bdsvm/dlx.c \
	libbdplus/bdsvm/interface.c \
	libbdplus/bdsvm/dlx.h \
	libbdplus/bdsvm/dlx_internal.h \
	libbdplus/bdsvm/diff.c \
	libbdplus/bdsvm/slot.c \
	libbdplus/bdsvm/trap.h \
	libbdplus/bdsvm/trap_helper.h \
	libbdplus/bdsvm/sha1.h \
	libbdplus/bdsvm/sha1.c \
	file/dirs.h \
	file/file.c \
	file/file.h \
	util/attributes.h \
	util/macro.h \
	util/mutex.h \
	util/strutl.c \
	util/strutl.h \
	util/logging.c \
	util/logging.h

if HAVE_DARWIN
libbdplus_la_SOURCES+= \
	file/dirs_darwin.c
else
if HAVE_WIN32
libbdplus_la_SOURCES+= \
	file/dirs_win32.c
else
libbdplus_la_SOURCES+= \
	file/dirs_xdg.c
endif
endif

pkginclude_HEADERS = \
	libbdplus/bdplus.h \
	libbdplus/bdplus-version.h

libbdplus_la_LDFLAGS= -no-undefined -version-info $(LT_VERSION_INFO)
libbdplus_la_LIBADD = $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS)
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libbdplus.pc


#
# examples
#

noinst_PROGRAMS = bdplus_test convtab_dump

bdplus_test_SOURCES = examples/bdplus_test.c
bdplus_test_CFLAGS  = $(AM_CFLAGS) $(LIBAACS_CFLAGS)
bdplus_test_LDADD   = libbdplus.la
bdplus_test_LDADD  += $(LIBAACS_LIBS)

convtab_dump_SOURCES = examples/convtab_dump.c
