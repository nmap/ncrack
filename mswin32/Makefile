MAKENSIS="/cygdrive/c/Program Files (x86)/NSIS/makensis.exe"
#VCEXPRESS := $(shell reg query "HKEY_CLASSES_ROOT\\Applications\\devenv.exe\\shell\\edit\\command" | egrep -i '[A-Z]:\\' | cut -d\" -f2 | sed 's%\\%/%g' | tr -d '\n')
VCEXPRESS="/cygdrive/c/Program Files (x86)/Microsoft Visual Studio 14.0/Common7/IDE/devenv.exe"
export NCRACK_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NCRACK_VERSION' ../ncrack.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export NCRACK_NUM_VERSION := $(shell grep '^\#[ \t]*define[ \t]\+NCRACK_NUM_VERSION' ../ncrack.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
COMMA_VERSION=$(shell echo $(NCRACK_NUM_VERSION) | tr '.' ',')
LOGLOC=c:ncrackbuild.log

winbuild: nsis/Ncrack.nsi LICENSE
# VCExpress.exe is devenv.com with the commercial Visual Studio suite instead of VC++ Express

	@./license-format/licformat.sh ../COPYING > LICENSE

	$(VCEXPRESS) ncrack.sln /build release /out $(LOGLOC)
	rm -rf ncrack-$(NCRACK_VERSION)
	mkdir ncrack-$(NCRACK_VERSION)
	cd Release && cp -r ../../COPYING ncrack-services ncrack.exe ../ncrack-$(NCRACK_VERSION)/
# Use "cmd /c copy" rather than "cp" to preserve Windows ACLs. Using
# "cp" means that the copied DLLs don't have the same ACL and cause an
# error on startup: 0xc0000022.
	cmd /c copy .\\OpenSSL\\bin\\*.dll ncrack-$(NCRACK_VERSION)\
	
	cp nsis/AddToPath.nsh nsis/Ncrack.nsi nsis/final.ini ncrack-$(NCRACK_VERSION)
	$(MAKENSIS) ncrack-$(NCRACK_VERSION)/Ncrack.nsi
	mv ncrack-$(NCRACK_VERSION)/NcrackInstaller.exe ncrack-$(NCRACK_VERSION)-setup.exe
	
	
nsis/Ncrack.nsi: nsis/Ncrack.nsi.in
	sed -e '1i; Automatically generated from $<.' \
	     -e 's/@@VIPRODUCTVERSION@@/"$(NCRACK_NUM_VERSION)"/' \
	     -e 's/@@VERSION@@/"$(NCRACK_VERSION)"/' \
	     "$<" > "$@"	

	
LICENSE: ../COPYING
	./license-format/licformat.sh "$<" > "$@"


clean:
	$(VCEXPRESS) ncrack.sln /clean
	rm -rf Debug Release ncrackbuild.log LICENSE
