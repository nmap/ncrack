MAKENSIS="/cygdrive/c/Program Files/NSIS/makensis.exe"
VCEXPRESS="/cygdrive/c/Program Files/Microsoft Visual Studio 10.0/Common7/IDE/VCExpress.exe"
export NCRACK_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NCRACK_VERSION' ../ncrack.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NCRACK_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NCRACK_NUM_VERSION' ../ncrack.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
COMMA_VERSION=$(shell echo $(NCRACK_NUM_VERSION) | tr '.' ',')
LOGLOC=c:ncrackbuild.log

winbuild:
# VCExpress.exe is devenv.com with the commercial Visual Studio suite instead of VC++ Express

	@./license-format/licformat.sh ../COPYING > LICENSE

	$(VCEXPRESS) ncrack.sln /build release /log $(LOGLOC)
	rm -rf ncrack-$(NCRACK_VERSION)
	mkdir ncrack-$(NCRACK_VERSION)
	cd Release && cp -r ../../COPYING ncrack-services ncrack.exe ../ncrack-$(NCRACK_VERSION)/
	cp -f OpenSSL/bin/*.dll ./ncrack-$(NCRACK_VERSION)/

	cp nsis/AddToPath.nsh nsis/Ncrack.nsi nsis/final.ini ncrack-$(NCRACK_VERSION)
	$(MAKENSIS) ncrack-$(NCRACK_VERSION)/Ncrack.nsi
	mv ncrack-$(NCRACK_VERSION)/NcrackInstaller.exe ncrack-$(NCRACK_VERSION)-setup.exe

clean:
	$(VCEXPRESS) ncrack.sln /clean
	rm -rf Debug Release ncrackbuild.log
