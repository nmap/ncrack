# Table of Contents
---
   
 * [Introduction](#intro)
 * [Requirements](#requ)
 * [Installation](#install)
 * [Files in this directory](#files)
 * [Repositories and Troubleshooting](#repo)

## <a name="intro"></a>Introduction

 * **Ncrack** is a free and open source network authentication cracking tool.

This package contains Ncrack. It is intended to work on Intel Macs running **Mac OS X 10.8 or later**.

The ncrack command-line binaries will be installed in `/usr/local/bin`, and additional support files will be installed in `/usr/local/share`. 


## <a name="requ"></a>Requirements

In order to compile, build and run Ncrack on Mac OS, you will requiere the followings:

1. **Jhbuild** for bundling and dependencies (see the [BUNDLING file](../BUNDLING.md))
2. **Xcode** for Mac OS 10.8 or later ([https://developer.apple.com/xcode](https://developer.apple.com/xcode/))
3. **Xcode Command-line Tools** for Mac OS 10.8 or later ([https://developer.apple.com/downloads](https://developer.apple.com/downloads/) — then download the latest version compatible with your OS version)

## <a name="install"></a>Installation

Ideally, you should be able to just type:

	./configure
	make
	make install
	
from `ncrack/` directory (the root folder).


## <a name="files"></a>Files in this directory

* [openssl.modules](openssl.modules): This is a Jhbuild moduleset that can be used to build dependencies (openssl) as required for building Ncrack. Use it like this:

	~~~~
	$ jhbuild -m openssl.modules build ncrack-deps
	~~~~
	
* [Makefile](Makefile): The Mac OS X Makefile used to build everything specific to this OS.
* [BUNDLING.md](BUNDLING.md): A manual on how to setup and use Jhbuild on Mac OS X.



## <a name="repo"></a>Repositories and Troubleshooting

Ncrack uses a read-only repository on **Github** for issues tracking and pull requests. You can contribute at the following address: [https://github.com/nmap/ncrack](https://github.com/nmap/ncrack).

