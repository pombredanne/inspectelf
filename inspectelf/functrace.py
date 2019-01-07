#!/usr/bin/python

import argparse
import os
import re
from elftools.elf.elffile import ELFFile
from capstone import *

def import_funcs(elffile):
	elf = ELFFile(open(elffile, "rb"))

	text = elf.get_section_by_name(".text")

	if text is None:
		raise Exception("No .text section found")

	plt = elf.get_section_by_name(".plt")

	if plt is None:
		raise Exception("No .plt section in file")

	plt_offset = text.header.sh_offset - plt.header.sh_offset

	rela_plt = elf.get_section_by_name(".rela.plt")

	if rela_plt is None:
		raise Exception("No .rela.plt relocation section in file")

	symtab = elf.get_section_by_name(".dynsym")

	if symtab is None:
		raise Exception("No string table in ELF file for relocatables")

	# Relocs index start from 1 somehow :S
	idx = 1
	relocs = []

	for reloc in rela_plt.iter_relocations():
		relocs.append({
				"name": symtab.get_symbol(reloc.entry.r_info_sym).name,
				"offset": plt.header.sh_addr + plt.header.sh_entsize * idx,
				"reloc": reloc
			})

		idx += 1

	return relocs

def import_match(elffile, names):
	imports = import_funcs(elffile)

	patterns = []

	# Prepare REs to find only as a whole word
	for n in names:
		# Beginning of symbol
		patterns.append(re.compile("^%s[0-9_]*" % n))

		# Middle
		patterns.append(re.compile(".*_%s[0-9_]*_" % n))

		# End
		patterns.append(re.compile(".*_%s[0-9]*$" % n))

		# Exact
		patterns.append(re.compile("^%s$" % n))

	found = []

	for i in imports:
		for p in patterns:
			if p.match(i["name"]) is not None:
				#print hex(i["offset"]), "(%s)\t" % hex(i["reloc"].entry.r_info_sym), i["name"]
				print hex(i["offset"]), "\t", i["name"]
				found.append(i)

				break
	return found

def find_usages(elffile, imports):
	elf = ELFFile(open(elffile, "rb"))

	text = elf.get_section_by_name(".text")

	if text is None:
		raise Exception("No .text section found")

	md = Cs(CS_ARCH_X86, CS_MODE_64)

	offset_map = {}
	offsets = []

	for x in imports:
		offsets.append(x["offset"])
		offset_map[x["offset"]] = x["name"]

	for i in md.disasm(text.data(), elf.header.e_entry):
		# print hex(i.address), i.mnemonic, i.op_str
		if i.mnemonic == "call":
			for offset in offsets:
				if hex(offset) in i.op_str:
					print "0x%x: Call to %s@plt" % (i.address, offset_map[offset])

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("elf", help = "ELF File")

	# Parse arguments
	args = parser.parse_args()

	find_usages(args.elf, import_match(args.elf, ["sha", "aes", "des", "md5", "memcpy"]))
