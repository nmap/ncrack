VCEXPRESS="/c/Program Files/Microsoft Visual Studio 9.0/Common7/IDE/VCExpress.exe"
LOGLOC=c:nmapbuild.log

winbuild:

	$(VCEXPRESS) ncrack.sln /build release /log $(LOGLOC)
	
clean:
	$(VCEXPRESS) nmap.sln /clean
	rm -rf Debug Release nmapbuild.log