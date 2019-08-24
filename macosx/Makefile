# This makefile builds a disk image (.dmg) containing the installer for Ncrack

NCRACK_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NCRACK_VERSION' ../ncrack.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
NCRACK_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NCRACK_NUM_VERSION' ../ncrack.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
OSX_VERSION=$(shell sw_vers -productVersion | cut -d'.' -f1,2 | tr -d ' ')
OSX_MIN_VERSION = 10.9

NAME_VERSION = ncrack-$(NCRACK_VERSION)$(if $(APPENDAGE),-$(APPENDAGE))

IMAGE_NAME = $(NAME_VERSION).dmg
PKG_NAME = $(NAME_VERSION).mpkg

IMAGE_STAGING_DIR = $(NAME_VERSION)

NCRACK_BUILD_DIR = ncrack-build
NCRACK_STAGING_DIR = Ncrack

JHBUILD_PREFIX=$(HOME)/gtk/inst
export JHBUILD_PREFIX
PREFIX = /usr/local

# Extra distribution file names
README_FILE = README.md
COPYING_FILE = COPYING
3RD_P_LIC_FILE = 3rd-party-licenses.txt
LICENSES_FILE = licenses

EXTRA_DIST = README.md ../COPYING ../docs/3rd-party-licenses.txt ../docs/licenses

CONFIGURE_ARGS = --prefix="$(PREFIX)" CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)" 

# Flags for building universal binaries. See
# http://developer.apple.com/documentation/Porting/Conceptual/PortingUnix/compiling/chapter_4_section_3.html.
UNIVERSAL_CONFIGURE_ARGS = --disable-dependency-tracking
UNIVERSAL_CC = gcc
UNIVERSAL_CXX = g++
# Setting ARCHFLAGS separately is required. distutils.util.get_platform
# sniffs it to determine whether to return a universal architecture
# ("fat" or "universal") or a single one ("i386" or "ppc"). py2app in
# turn uses the arch value to decide which of its bootstrappers to
# install.
UNIVERSAL_ARCHFLAGS = -arch x86_64
UNIVERSAL_CPPFLAGS = -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX$(OSX_VERSION).sdk
UNIVERSAL_CFLAGS = $(UNIVERSAL_CPPFLAGS) -mmacosx-version-min=$(OSX_MIN_VERSION) $(UNIVERSAL_ARCHFLAGS)
UNIVERSAL_CXXFLAGS = $(UNIVERSAL_CFLAGS) -stdlib=libc++
# https://stackoverflow.com/questions/19637164/c-linking-error-after-upgrading-to-mac-os-x-10-9-xcode-5-0-1/19637199#19637199
UNIVERSAL_LDFLAGS = -stdlib=libc++ -Wl,-syslibroot,/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX$(OSX_VERSION).sdk -mmacosx-version-min=$(OSX_MIN_VERSION) $(UNIVERSAL_ARCHFLAGS)

CC = $(UNIVERSAL_CC)
CXX = $(UNIVERSAL_CXX)
ARCHFLAGS += $(UNIVERSAL_ARCHFLAGS)
CONFIGURE_ARGS += $(UNIVERSAL_CONFIGURE_ARGS)
CPPFLAGS += $(UNIVERSAL_CPPFLAGS)
CFLAGS += $(UNIVERSAL_CFLAGS)
CXXFLAGS += $(UNIVERSAL_CXXFLAGS)
LDFLAGS += $(UNIVERSAL_LDFLAGS)


# Jhbuild static libraries
OPENSSL_STATIC = $(JHBUILD_PREFIX)/lib/libssl.a $(JHBUILD_PREFIX)/lib/libcrypto.a
LIBZ_STATIC = $(JHBUILD_PREFIX)/lib/libz.a

# These are the positions used by the createdmg.sh and check_test.sh scripts
export ICON_SIZE=88
export FONT_SIZE=13
export MPKG_POS_X=110
export MPKG_POS_Y=170
export APPS_POS_X=110
export APPS_POS_Y=310
export README_POS_X=802
export README_POS_Y=180
export COPYING_POS_X=802
export COPYING_POS_Y=310
export THIRD_P_POS_X=802
export THIRD_P_POS_Y=440
export LICENSES_POS_X=670
export LICENSES_POS_Y=60

$(IMAGE_NAME): tool-checks $(IMAGE_STAGING_DIR)/$(PKG_NAME)
	rm -f $@
	# Create the dmg disk image and convert it to read only disk
	./createdmg.sh $(IMAGE_STAGING_DIR) $(README_FILE) $(COPYING_FILE) $(3RD_P_LIC_FILE) $(LICENSES_FILE)
	# Check the created disk image for the sizes, backgrounds and icons presence and positions
	./check_test.sh $(README_FILE) $(COPYING_FILE) $(3RD_P_LIC_FILE) $(LICENSES_FILE)

tool-checks: have-$(CC) have-jhbuild have-gtk-mac-bundler

have-%:
	which $*

$(IMAGE_STAGING_DIR)/$(PKG_NAME): check-ncrack COPYING.formatted
	mkdir -p $(IMAGE_STAGING_DIR)
	cp -rf $(EXTRA_DIST) $(IMAGE_STAGING_DIR)/
	# Create packages (.pkg) for all the components to install in the installer (.mpkg)
	pkgbuild --root $(NCRACK_STAGING_DIR) --identifier org.insecure.nmap --version $(NCRACK_VERSION) --install-location / ncrack.pkg

	# Produce a .xml with packages information
	productbuild --synthesize \
		--package 'ncrack.pkg' \
		distribution.xml

	# Make a new file and add background and title attributes
	head -n 2 distribution.xml > finalDist.xml
	echo "    <title>Ncrack $(NCRACK_VERSION)</title>" >> finalDist.xml
	# This line is for adding a background image to the .mpkg
	echo "    <background file=\"pkg_bg.jpg\" mime-type=\"image/jpeg\" scaling=\"proportional\" alignment=\"bottomleft\"/>" >> finalDist.xml
	tail -n +3 distribution.xml >> finalDist.xml

	# Build the .mpkg according to the final .xml file (and so all the .pkg)
	productbuild --distribution finalDist.xml --resources . --package-path . $(NAME_VERSION).mpkg

	mv $(NAME_VERSION).mpkg $(NAME_VERSION)/$(NAME_VERSION).mpkg
	rm -rf distribution.xml finalDist.xml ncrack.pkg 

check-%: stage-%
	#if (find $* -perm -a+x -type f | xargs otool -L | grep -F "$(JHBUILD_PREFIX)"); then false; else echo "Libs are clean"; fi

export-%:
	rm -rf $*
# Using @BASE discards local changes.
	mkdir ncrack-build
	cd .. && git archive master | tar -x -C macosx/ncrack-build

stage-ncrack: export-$(NCRACK_BUILD_DIR)
	cd $(NCRACK_BUILD_DIR) && ./configure --with-openssl="$(JHBUILD_PREFIX)" --with-libz="$(JHBUILD_PREFIX)" $(CONFIGURE_ARGS)
	# LIB* is libssh2's name for *_LIBS
	make -C $(NCRACK_BUILD_DIR) OPENSSL_LIBS="$(OPENSSL_STATIC)" LIBSSL="$(OPENSSL_STATIC)" ZLIB_LIBS="$(LIBZ_STATIC)" LIBZ="$(LIBZ_STATIC)"
	rm -rf $(NCRACK_STAGING_DIR)
	make -C $(NCRACK_BUILD_DIR) install DESTDIR="`pwd`/$(NCRACK_STAGING_DIR)" OPENSSL_LIBS="$(OPENSSL_STATIC)" ZLIB_LIBS="$(LIBZ_STATIC)"


# make-bundle.sh uses these to build its authorization wrapper.
export CC ARCHFLAGS CPPFLAGS CFLAGS CXXFLAGS LDFLAGS


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
