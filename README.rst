Inspectelf - ELF inspection utilities
========

This project holds various scripts and utilities that aid in investigating ELF files.
Some of the given analysis scripts are given as-is and will work out-of-the-box, and some
require some setup. Following is the list of utilities, their purposes and how to use them:

Quickstart
----------
Install via ``python ./setup.py install``.

Utilities
---------
* ``cflags.py`` - Analyzes an ELF file and outputs which compilation flags were used in build time
* ``cfuncs.py`` - A ctags utility that outputs all C function signatures from a source directory
* ``cstrings.py`` - A clang utility that builds an AST of given source code file to extract funcions and strings
* ``functrace[|_arm|_aarch64].py`` - A static utility that analyzes an ARM/AARCH64 binary file for functions and call stacks
* ``kconfig.py`` - A Linux Kernel security configuration utility that verifies a secure configuration build over binary Linux kernel image
- versions* - A subsystem for analyzing binary files for their open source project name and versions. Requires either a RedisDB or MongoDB setup
    * ``versions_download.py`` - A download script, receiving either an HTTP directory listing, github releases page or any HTML page that contains links to *.tar.gz *source* packages, downloads them and arranges them in a directory structure underlying their project and version
    * ``versions_similarity.py`` - The next stage in the version matching process - a scanning / analysis utility scans the downloaded packages, parses them and inserts relevant data from source packages to the database with the 'scan' function over the downloads folder. Later, the 'identify' function over a binary file, utilizes the data gathered to the database in order to figure out what open source version is this file. 
    * ``versions_cve.py`` - A short utility to gather all CVEs for a project and version number
    * ``versions_db.py`` - A python command line accessing the database as python objects
