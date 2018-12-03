#!/usr/bin/python

import argparse
import pprint
from os import path
from elftools.elf.elffile import ELFFile
from capstone import *

def dedouble(s, c):
	now = s.replace(c * 2, c)

	while now != s:
		s = now
		now = s.replace(c * 2, c)

	return now

def x64_parse(e):
	MECHANISMS = {"STACK_CANARIES": False}

	md = Cs(CS_ARCH_X86, CS_MODE_64)
	text = get_section(e, ".text")
	for i in md.disasm(text.data(), 0):
		if i.mnemonic == "xor" and "fs:[0x28]" in i.op_str:
			MECHANISMS["STACK_CANARIES"] = True
			break

	return MECHANISMS

WORK_ARCH = None
ARCHS = {
		"EM_X86_64":
		{
			"PARSE": x64_parse,
			"LIBS": ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"]
		},

		"EM_ARM":
		{
			"PARSE": None,
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

def inspect(elffile, sysroot = "/", recursive = False, LIBRARIES = {}):
	global WORK_ARCH

	if elffile in LIBRARIES:
		return

	with open(elffile, "rb") as f:
		e = ELFFile(f)

		if WORK_ARCH is None:
			WORK_ARCH = e.header.e_machine
		elif e.header.e_machine != WORK_ARCH:
			# Mistakenly parsing wrong library
			return

		print "Inspecting %s" % elffile

		MECHANISMS = {
					"PIE": False,
					"STACK_CANARIES": False,
					"STRIPPED": False,
					"RELRO": False,
					"SANITIZE_ADDR": False,
					"FORTIFY_SOURCE": False
				}

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

		if not recursive:
			return LIBRARIES

		dynstr = get_section(e, ".dynstr")
		rpaths = [ path.sep.join((sysroot, x)) for x in ["/lib/", "/usr/lib/"]]

		# Add architecture dependent paths
		rpaths += [ path.sep.join((sysroot, x)) for x in ARCHS[e.header.e_machine]["LIBS"]]

		# Recurse over all other dependencies
		for tag in get_section(e, ".dynamic").iter_tags():
			if tag.entry.d_tag == "DT_NEEDED":
				library = dynstr.get_string(tag.entry.d_val)
				for rpath in rpaths:
					p = dedouble(path.sep.join((rpath, library)), '/')

					if path.exists(p):
						inspect(p, sysroot, recursive, LIBRARIES)
						# Continue looking for other candidates as we might be confusing
						# host libraries with actual sysroot ones
						break

			elif tag.entry.d_tag == "DT_RPATH":
				rpaths.append(path.sep.join((sysroot, dynstr.get_string(tag.entry.d_val))))

	return LIBRARIES


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-s", "--sysroot", help = "Folder that holds system root (for cross compiled binaries)")
	parser.add_argument("-r", "--recursive", help = "Continue parsing recursively over dependencies", action="store_true")
	parser.add_argument("file", help = "ELF File for parsing")
	args = parser.parse_args()
	if args.sysroot is None:
		args.sysroot = "/"

	if args.recursive is None:
		args.recursive = False

	LIBRARIES = inspect(args.file, args.sysroot, args.recursive)
	pprint.PrettyPrinter(indent=4).pprint(LIBRARIES)
