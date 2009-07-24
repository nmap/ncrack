
all: man

man: ncrack-man-enclosure.xml refguide.xml xsl/man.nroff.xsl
	xsltproc --stringparam doc.class man --xinclude --output ncrack.1 xsl/man.nroff.xsl ncrack-man-enclosure.xml
