# This makefile builds a disk image (.dmg) containing the installer for Ncrack

NCRACK_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NCRACK_VERSION' ../ncrack.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
NCRACK_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NCRACK_NUM_VERSION' ../ncrack.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')

NAME_VERSION = ncrack-$(NCRACK_VERSION)$(if $(APPENDAGE),-$(APPENDAGE))

IMAGE_NAME = $(NAME_VERSION).dmg
PKG_NAME = $(NAME_VERSION).mpkg

IMAGE_STAGING_DIR = $(NAME_VERSION)

NCRACK_BUILD_DIR = ncrack-build
NCRACK_STAGING_DIR = Ncrack

PREFIX = /usr/local

PACKAGEMAKER = /Developer/usr/bin/packagemaker

EXTRA_DIST_FILES = $(addprefix $(IMAGE_STAGING_DIR)/,COPYING README)

CONFIGURE_ARGS = --prefix="$(PREFIX)" CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)"

# Flags for building universal binaries. See
# http://developer.apple.com/documentation/Porting/Conceptual/PortingUnix/compiling/chapter_4_section_3.html.
UNIVERSAL_CONFIGURE_ARGS = --disable-dependency-tracking
# gcc-4.0 is used to avoid an error with stdarg.h ("No such file or directory")
# when building against the 10.4u SDK on OS X 10.6.
UNIVERSAL_CC = gcc-4.0
UNIVERSAL_CXX = g++-4.0
UNIVERSAL_CPPFLAGS = -isysroot /Developer/SDKs/MacOSX10.4u.sdk
UNIVERSAL_CFLAGS = $(UNIVERSAL_CPPFLAGS) -mmacosx-version-min=10.4 -arch ppc -arch i386
UNIVERSAL_CXXFLAGS = $(UNIVERSAL_CFLAGS)
UNIVERSAL_LDFLAGS = -Wl,-syslibroot,/Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4 -arch ppc -arch i386

CC = $(UNIVERSAL_CC)
CXX = $(UNIVERSAL_CXX)
CONFIGURE_ARGS += $(UNIVERSAL_CONFIGURE_ARGS)
CPPFLAGS += $(UNIVERSAL_CPPFLAGS)
CFLAGS += $(UNIVERSAL_CFLAGS)
CXXFLAGS += $(UNIVERSAL_CXXFLAGS)
LDFLAGS += $(UNIVERSAL_LDFLAGS)

$(IMAGE_NAME): $(IMAGE_STAGING_DIR)/$(PKG_NAME) $(EXTRA_DIST_FILES)
	rm -f $@
	hdiutil create -imagekey zlib-level=9 -srcfolder $(IMAGE_STAGING_DIR) $@

$(IMAGE_STAGING_DIR)/$(PKG_NAME): stage-ncrack README COPYING.formatted
	mkdir -p $(IMAGE_STAGING_DIR)
	$(PACKAGEMAKER) --doc ncrack.pmdoc --id org.insecure.ncrack --title "Ncrack $(NCRACK_VERSION)" -o $@

export-%:
	rm -rf $*
# Using @BASE discards local changes.
	svn export ..@BASE $*

stage-ncrack: export-$(NCRACK_BUILD_DIR)
	cd $(NCRACK_BUILD_DIR) && ./configure $(CONFIGURE_ARGS)
	make -C $(NCRACK_BUILD_DIR)
	rm -rf $(NCRACK_STAGING_DIR)
	make -C $(NCRACK_BUILD_DIR) install DESTDIR="`pwd`/$(NCRACK_STAGING_DIR)"


# make-bundle.sh uses these to build its authorization wrapper.
export CC CPPFLAGS CFLAGS CXXFLAGS LDFLAGS

$(IMAGE_STAGING_DIR)/README:
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -f README $(IMAGE_STAGING_DIR)/

$(IMAGE_STAGING_DIR)/COPYING:
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -f ../COPYING $(IMAGE_STAGING_DIR)/

COPYING.formatted:
# Use the license formatter from the Windows installer.
	../mswin32/license-format/licformat.sh ../COPYING > $@

clean:
	rm -rf $(IMAGE_STAGING_DIR)
	rm -rf $(NCRACK_BUILD_DIR)
	rm -rf $(NCRACK_STAGING_DIR)

	rm -f COPYING.formatted
	rm -f $(IMAGE_NAME)

.PHONY: clean export-% stage-%
