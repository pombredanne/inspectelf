#!/usr/bin/python

import argparse
import pprint
import hashlib
import Levenshtein
import json
from os import path, mkdir, listdir
from elftools.elf.elffile import ELFFile
from capstone import *
from binascii import hexlify

def dedouble(s, c):
	now = s.replace(c * 2, c)

	while now != s:
		s = now
		now = s.replace(c * 2, c)

	return now

def x64_parse(e):
	return {}

def arm_parse(e):
	return {}

def aarch64_parse(e):
	return {}

WORK_ARCH = None
ARCHS = {
		"EM_X86_64":
		{
			"PARSE": x64_parse,
			"LIBS": ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"]
		},

		"EM_ARM":
		{
			"PARSE": arm_parse,
			"LIBS": []
		},

		"EM_AARCH64":
		{
			"PARSE": aarch64_parse,
			"LIBS": []
		}
	}

def get_section(e, name):
	for section in e.iter_sections():
		if section.name == name:
			return section

def get_segments(e, name):
	s = []
	for segment in e.iter_segments():
		if segment.header.p_type == name:
			s.append(segment)

	return s

def inspect(elffile, sysroot = "/", recursive = False, cfg = False, force = False, LIBRARIES = None, WORK_ARCH = None):
	if LIBRARIES is None:
		LIBRARIES = {}

	if elffile in LIBRARIES:
		return LIBRARIES[elffile]

	with open(elffile, "rb") as f:
		e = ELFFile(f)

		if WORK_ARCH is None:
			WORK_ARCH = e.header.e_machine
		elif e.header.e_machine != WORK_ARCH:
			# Mistakenly parsing wrong library
			return

		print "Inspecting %s" % elffile

		# Create a DB if does not exist
		if not path.exists("db/"):
			mkdir("db/")

		MECHANISMS = {
					"ELF-FILENAME": path.basename(elffile),
					"DEPENDENCIES": [],
					"PIE": False,
					"STACK_CANARIES": False,
					"STRIPPED": False,
					"RELRO": False,
					"SANITIZE_ADDR": False,
					"FORTIFY_SOURCE": False
				}

		# Create file hash
		sha256 = hashlib.sha256()
		with open(elffile, "rb") as f:
			sha256.update(f.read())
			digest = sha256.digest().encode("HEX")
			MECHANISMS["ELF-HASH"] = digest

		# Try reading from DB
		if path.exists("db/%s.json" % path.basename(elffile)):
			with open("db/%s.json" % path.basename(elffile), "rb") as fp:
				record = json.load(fp)
				if digest == record["ELF-HASH"]:
					if not force:
						# Remember to delete BLOOM
						if "BLOOM" in record:
							del record["BLOOM"]
						return { elffile: record }
					else:
						# If this is forced, reanalyze everything
						# but have this record here just in case (Hint: For CFG Analysis)
						MECHANISMS = record


		# Check for PIE
		text = get_section(e, ".text")

		if e.header.e_entry == text.header.sh_addr or e.header.e_type == "ET_DYN":
			MECHANISMS["PIE"] = True

		# Check for stripped binary
		strtab = get_section(e, ".strtab")
		symtab = get_section(e, ".symtab")

		if strtab is None and symtab is None:
			MECHANISMS["STRIPPED"] = True

		# Check if RELRO
		if len(get_segments(e, "PT_GNU_RELRO")) > 0:
			MECHANISMS["RELRO"] = True

		# Get dynsym
		dynsym = get_section(e, ".dynsym")
		if dynsym.get_symbol_by_name("__asan_init_v4") is not None:
			MECHANISMS["SANITIZE_ADDR"] = True

		if dynsym.get_symbol_by_name("__stack_chk_guard") is not None:
			MECHANISMS["STACK_CANARIES"] = True

		# Check _FORTIFY_SOURCE
		for symbol in dynsym.iter_symbols():
			if symbol.name.startswith("__") and symbol.name.endswith("_chk"):
				MECHANISMS["FORTIFY_SOURCE"] = True

		# Figure out ELF Arch
		if e.header.e_machine in ARCHS and ARCHS[e.header.e_machine]["PARSE"] is not None:
			m = ARCHS[e.header.e_machine]["PARSE"](e)

			# Arch dependent checks
			for k in m.keys():
				MECHANISMS[k] = m[k]

		LIBRARIES[elffile] = MECHANISMS

		dynstr = get_section(e, ".dynstr")
		rpaths = [ path.sep.join((sysroot, x)) for x in ["/lib/", "/usr/lib/"]]

		# Add architecture dependent paths
		rpaths += [ path.sep.join((sysroot, x)) for x in ARCHS[e.header.e_machine]["LIBS"]]

		# Recurse over all other dependencies
		for tag in get_section(e, ".dynamic").iter_tags():
			if tag.entry.d_tag == "DT_NEEDED":
				library = dynstr.get_string(tag.entry.d_val)
				MECHANISMS["DEPENDENCIES"].append(library)

				if recursive:
					for rpath in rpaths:
						p = dedouble(path.sep.join((rpath, library)), '/')

						if path.exists(p):
							inspect(p, sysroot = sysroot, recursive = recursive, cfg = cfg, force = force, LIBRARIES = LIBRARIES, WORK_ARCH = WORK_ARCH)
							# Continue looking for other candidates as we might be confusing
							# host libraries with actual sysroot ones
							break

			elif tag.entry.d_tag == "DT_RPATH":
				LIB_RPATH = path.sep.join((sysroot, dynstr.get_string(tag.entry.d_val)))

				# Add library-added RPATHs
				MECHANIMS["RPATH"] = LIB_RPATH

				rpaths.append(LIB_RPATH)

	# Save MECHANISMS to file only if activated as a separate utility
	if __name__ == "__main__":
		with open("db/%s.json" % path.basename(elffile), "wb") as f:
			json.dump(MECHANISMS, f)

	# Before returning to user, remove bloom filters as it's not interestnig anywhere but here
	for lib in LIBRARIES:
		if "BLOOM" in LIBRARIES[lib]:
			del LIBRARIES[lib]["BLOOM"]

	return LIBRARIES


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Inspect ELF Files for build-time compiler flags")
	parser.add_argument("-s", "--sysroot", help = "Folder that holds system root (for cross compiled binaries)")
	parser.add_argument("-r", "--recursive", help = "Continue parsing recursively over dependencies", action = "store_true")
	parser.add_argument("-c", "--cfg", help = "Build static CFG signatures", action = "store_true")
	parser.add_argument("-f", "--force", help = "Force reanalysis", action = "store_true")
	parser.add_argument("file", help = "ELF File for parsing")
	args = parser.parse_args()
	if args.sysroot is None:
		args.sysroot = "/"

	if args.recursive is None:
		args.recursive = False

	if args.cfg is None:
		args.cfg = False

	if args.force is None:
		args.force = False

	LIBRARIES = inspect(args.file, sysroot = args.sysroot, recursive = args.recursive, cfg = args.cfg, force = args.force)

	# On command line, ignore strings
	for lib in LIBRARIES:
		if "ELF-STRINGS" in LIBRARIES[lib]:
			del LIBRARIES[lib]["ELF-STRINGS"]

	pprint.PrettyPrinter(indent=4).pprint(LIBRARIES)
