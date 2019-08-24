# Table of Contents
---
   
 * [Jhbuild](#jhbuild)
 	* Observation
 	* Possible error
 * [gtk-mac-bundler](#bundler)
 * [How to use](#howto)
 	* Prerequisite
 	* Usage

## <a name="jhbuild"></a>Jhbuild

In order to set up Jhbuild properly before building Ncrack, follow the tutorial at [https://wiki.gnome.org/Projects/GTK%2B/OSX/Building](https://wiki.gnome.org/Projects/GTK%2B/OSX/Building), but keep reading this file if you encounter any error...

If you had any error, just type the following command to delete jhbuild,

	$ rm -rf ~/bin/jhbuild ~/.local/bin/jhbuild ~/.local/share/jhbuild ~/.cache/jhbuild ~/.config/jhbuildrc ~/.jhbuildrc ~/.jhbuildrc-custom ~/jhbuild

And we'll start over together:

1.	First, simply download the following script in your _$HOME_ directory and launch it ([https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh](https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh)):

	~~~~
	$ sh gtk-osx-build-setup.sh
	~~~~
	
	And add it to your _$PATH_, so you can run jhbuild without the absolute path:
	
	~~~~
	$ export PATH=$HOME/.local/bin:$PATH
	~~~~
	
2.	In `~/.jhbuildrc-custom`, make sure that this line is setup properly:

	~~~~
	setup_sdk(target=_target, sdk_version="native", architectures=["x86_64"])
	~~~~
	
	for an x86_64 architecture. Latest macOS versions do not support i386.
	
3.	Now do,

	~~~~
	$ jhbuild bootstrap
	~~~~
	
	To install missing dependencies (with **--force** option to force rebuilding).<br/>Go to **Observation** if errors appear...
	
4.	And,

	~~~~
	$ jhbuild build meta-gtk-osx-bootstrap
	$ jhbuild build meta-gtk-osx-core
	~~~~
	
	Go to **Observation** if errors appear... 
	
<br/>
### Observation
	
If anything goes wrong now, it'll probably be a bad link on your python binary, so check that you're using the **GTK one** instead of the original mac one:

~~~~	
$ jhbuild shell
bash$ which python
~~~~

If you can see _gtk_ in the path, everything is fine with Python, else do:

~~~~
$ jhbuild build --force python
~~~~

And make an alias, to use this version of Python with Jhbuild:

~~~~
$ alias jhbuild="PATH=gtk-prefix/bin:$PATH jhbuild"
~~~~

Now continue at **step 3** with the --force option at the end of each command, to reinstall everything from scratch with this new python binary.


## <a name="bundler"></a>gtk-mac-bundler

Now that Jhbuild is properly configured, we need to install **gtk-mac-bundler** in order to render the bundle file:

~~~~
$ git clone git://git.gnome.org/gtk-mac-bundler
$ cd gtk-mac-bundler
$ make install
~~~~

## <a name="howto"></a>How to use
#### Prerequisite:
—`openssl.modules`:

This is a jhbuild moduleset that can be used to build/update openssl 

#### Usage:

Now use it like this:
    
~~~~
$ jhbuild -m openssl.modules build ncrack-deps
~~~~
