#!/usr/bin/python

import argparse
import os
import re
from elftools.elf.elffile import ELFFile
from capstone import *

class CallNode:
	def __init__(self):
		self.addr = 0
		self.usages = {}

def import_funcs(elffile):
	elf = ELFFile(open(elffile, "rb"))

	text = elf.get_section_by_name(".text")

	if text is None:
		raise Exception("No .text section found")

	plt = elf.get_section_by_name(".plt")

	if plt is None:
		raise Exception("No .plt section in file")

	plt_offset = text.header.sh_offset - plt.header.sh_offset

	# print "PLT Offset: 0x%x" % plt.header.sh_addr

	rela_plt = elf.get_section_by_name(".rela.plt")

	if rela_plt is None:
		rela_plt = elf.get_section_by_name(".rel.plt")
		if rela_plt is None:
			raise Exception("No .rel[a].plt relocation section in file")

	symtab = elf.get_section_by_name(".dynsym")

	if symtab is None:
		raise Exception("No string table in ELF file for relocatables")

	# Relocs index start from 1 somehow :S
	idx = 2
	startoff = 0

	# Per architecture mods
	if elf.header.e_machine == "EM_ARM":
		if plt.header.sh_entsize == 0:
			plt.header.sh_entsize = 12
			startoff = 8

	relocs = {}

	for reloc in rela_plt.iter_relocations():
		r = {
				"name": symtab.get_symbol(reloc.entry.r_info_sym).name,
				"offset": plt.header.sh_addr + startoff + plt.header.sh_entsize * idx,
				"reloc": reloc,
				"index": idx
			}

		# Map it according to offset, as all accesses will be accordingly
		relocs[r["offset"]] = r

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

	found = {}

	for i in imports:
		for p in patterns:
			if p.match(imports[i]["name"].lower()) is not None:
				#print hex(i["offset"]), "(%s)\t" % hex(i["reloc"].entry.r_info_sym), i["name"]
				# print hex(imports[i]["offset"]), " (%d)\t" % imports[i]["index"], imports[i]["name"]
				found[imports[i]["offset"]] = imports[i]

				break
	return found

def find_usages(elffile, addresses):
	elf = ELFFile(open(elffile, "rb"))

	text = elf.get_section_by_name(".text")

	if text is None:
		raise Exception("No .text section found")

	if elf.header.e_machine == "EM_X86_64":
		arch = CS_ARCH_X86
		mode = CS_MODE_64
		mnemonic = "call"
		pattern = "#(0x[a-f0-9]+)"
	elif elf.header.e_machine == "EM_ARM":
		arch = CS_ARCH_ARM
		mode = CS_MODE_ARM
		mnemonic = "bl"
		pattern = "#(0x[a-f0-9]+)"
	elif elf.header.e_machine == "EM_AARCH64":
		arch = CS_ARCH_ARM64
		mode = CS_MODE_ARM
		mnemonic = "bl"
		pattern = "#(0x[a-f0-9]+)"

	md = Cs(arch, mode)

	md.skipdata = True

	usages = {}

	#for i in md.disasm(text.data(), elf.header.e_entry):
	for i in md.disasm(text.data(), text.header.sh_addr):
		if i.mnemonic == mnemonic:
			for offset in addresses:
				m = re.match(pattern, i.op_str)
				if m is None:
					continue
				addr = int(m.groups()[0], 16)

				if addr == offset:
					# print "0x%x: Call to %s" % (i.address, addresses[offset]["name"])

					# Create a list of usages
					if offset not in usages:
						usages[offset] = []

					# Add usage pointer
					usages[offset].append(i.address)

	return usages

def find_functions_aarch64(section, found_funcs, terminating = []):
	md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

	md.skipdata = True

	# Start with first address of section
	addresses = [section.header.sh_addr]

	functions = {}
	expected_functions = []

	branches = [
			{"mnemonic": "b", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "b.ls", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "b.ne", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "b.cs", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "b.eq", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "b.hi", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "b.cc", "arg": "#(0x[0-9a-f]+)"},
	 		{"mnemonic": "cbz", "arg": "x[0-9]+, #(0x[0-9a-f]+)"},
	 		{"mnemonic": "tbz", "arg": "[rw][0-9], #x[0-9]+, #(0x[0-9a-f]+)"}
	 	]

	calls = [
			{"mnemonic": "bl", "arg": "#(0x[0-9a-f]+)"}
		]
	nops = [
			bytes("\x00\x00\x00\x00"),
			bytes("\x1f\x20\x03\xd5")
		]

	# print "Section address: 0x%x" % section.header.sh_addr


	for i in md.disasm(section.data(), section.header.sh_addr):
		# print hex(i.address), "(0x%x-0x%x)" % (addresses[0],addresses[-1]), i.mnemonic, i.op_str

		# Skip NOPs in function prolog
		if len(addresses) == 1 and addresses[0] == i.address:
			skip_nop = False
			# print str(i.bytes).encode("hex")
			for nop in nops:
				if i.bytes == nop:
					#@if len(addresses) == 1 and addresses[0] == i.address and i.mnemonic == "nop":
					addresses = [i.address + 4]
					skip_nip = True
					break

			if skip_nop:
				continue

		# Is this the end of the function?
		# Marked as a return clause that has no referenced addresses further ahead
		# in the assembly
		if i.mnemonic == "ret" and i.address >= addresses[-1]:
			if addresses[0] in expected_functions:
				#print "Found expected function: 0x%x" % addresses[0]

				expected_functions.remove(addresses[0])

			# Found a function end.
			functions[addresses[0]] = i.address - addresses[0] + 4

			print "Found function (RET): 0x%x (%d)" % (addresses[0], functions[addresses[0]])

			# Start looking at a new function
			addresses = [i.address + 4]

			continue
		elif i.mnemonic == "ret":
			pass
			# print "RET at 0x%x Farthest ptr: 0x%x" % (i.address, addresses[-1])

		for c in calls:
			if i.mnemonic == c["mnemonic"]:
				m = re.match(c["arg"], i.op_str)

				if m is None:
					continue

				nextaddr = int(m.groups()[0], 16)

				if nextaddr in terminating:
					if addresses[0] in expected_functions:
						#print "Found expected function: 0x%x" % addresses[0]

						expected_functions.remove(addresses[0])

					# Found a function end.
					functions[addresses[0]] = i.address - addresses[0] + 4

					print "Found function (TERMINATING CALL): 0x%x (%d)" % (addresses[0], functions[addresses[0]])

					# Start looking at a new function
					addresses = [i.address + 4]
				else:
					if nextaddr not in expected_functions:
						expected_functions.append(nextaddr)

		for b in branches:
			if i.mnemonic == b["mnemonic"]:
				# Look for the argument
				m = re.match(b["arg"], i.op_str)

				if m is None:
					continue

				nextaddr = int(m.groups()[0], 16)

				# This is a DECLARED FUNCTION that I've found. Ignore this branch.
				if nextaddr in found_funcs:
					break

				# Too long a jump??
				if nextaddr - i.address > 4096 * 2:
					break

				# Check if it's the furthest branch and is pointing back inside the function
				if ((i.address >= addresses[-1]) and (i.address >= nextaddr) and (i.address >= addresses[-1])) or (nextaddr in terminating):
					if addresses[0] in expected_functions:
						# print "Found expected function: 0x%x" % addresses[0]

						expected_functions.remove(addresses[0])

					# Found a function end.
					# if i.address > 0x423230:
					functions[addresses[0]] = i.address - addresses[0] + 4

					print "Found function (BACK JMP): 0x%x (%d)" % (addresses[0], functions[addresses[0]])

					# Start looking at a new function
					addresses = [i.address + 4]
				else:
					# print "Next addr: 0x%x End addr: 0x%x" % (nextaddr, addresses[-1])
					addresses.append(nextaddr)
					addresses.sort()
				break

	k = functions.keys()
	k.sort()

	for x in functions:
		if x in expected_functions:
			expected_functions.remove(x)

	for x in found_funcs:
		if x in expected_functions:
			expected_functions.remove(x)

	expected_functions.sort()
	# print "Functions:", [ (hex(x), functions[x]) for x in k ]
	# print "Expected (unfound) functions:", [ hex(x) for x in expected_functions ]
	return functions

def find_functions(elffile):
	elf = ELFFile(open(elffile, "rb"))

	text = elf.get_section_by_name(".text")

	if text is None:
		raise Exception("No .text section found")

	dynsym = elf.get_section_by_name(".dynsym")

	if dynsym is None:
		raise Exception("No .dynsym section found")

	found_funcs = []

	for sym in dynsym.iter_symbols():
		if sym.entry.st_value != 0:
			found_funcs.append(sym.entry.st_value)

	imports = import_funcs(elffile)

	# Add imported functions
	found_funcs += [ imports[x]["offset"] for x in imports ]

	# filter terminating branches
	terminating = ["abort", "__stack_chk_fail"]
	terminating_funcs = filter(lambda x: x is not None, [ imports[x]["offset"] if imports[x]["name"] in terminating else None for x in imports ])

	# print "Found Imports:", [hex(x) for x in found_funcs]

	if elf.header.e_machine == "EM_AARCH64":
		return find_functions_aarch64(text, found_funcs, terminating_funcs)

def find_symbols(elffile):
	elf = ELFFile(open(elffile, "rb"))

	symtab = elf.get_section_by_name(".symtab")

	if symtab is None:
		raise Exception("No .symtab section found")

	symbols = {}

	for s in symtab.iter_symbols():
		if s.entry.st_value == 0:
			continue
		symbols[s.entry.st_value] = s.name

	return symbols

def find_addr_in_range(addr, ranges):
	r = filter(lambda r: r[0] < addr < r[1], ranges)

	if len(r) != 1:
		return None
	else:
		return r[0][0]

def callstack(elffile, addr, function_ranges, child, depth = 0):
	calling_function = find_addr_in_range(addr, function_ranges)

	node = CallNode()
	node.addr = calling_function

	child.usages[addr] = node

	if calling_function is None:
		return child

	usages = find_usages(elffile, {calling_function: {"name": ""}})
	for func in usages:
		for u in usages[func]:
			callstack(elffile, u, function_ranges, node, depth + 1)

	return child

def print_callstack(node, symbols, imports, depth = 0, callpoint = None):
	if node.addr in symbols:
		funcname = "%s@0x%x" % (symbols[node.addr], node.addr)
	elif node.addr in imports:
		funcname = "%s@.plt@0x%x" % (imports[node.addr]["name"], node.addr)
	else:
		funcname = "unnamed@0x%x" % (node.addr)

	if callpoint is None:
		print "\t" * depth, funcname
	else:
		print "\t" * depth, "from 0x%x" % callpoint, "at", funcname

	for u in node.usages:
		print_callstack(node.usages[u], symbols, imports, depth + 1, u)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("elf", help = "ELF File")

	# Parse arguments
	args = parser.parse_args()

	# Find all functions within the ELF object
	functions = find_functions(args.elf)
	ranges = [(ptr, ptr + functions[ptr]) for ptr in functions]

	# Hold all imports + symbols
	imports = import_funcs(args.elf)

	# File all imports of given pattern
	selected_imports = import_match(args.elf, ["sha", "aes", "des", "md5", "memcpy", "memset"])
	# selected_imports = import_match(args.elf, ["sha"])

	# Find all the usages of the following functions
	usages = find_usages(args.elf, selected_imports)

	symbols = find_symbols(args.elf)

	for candidate in usages:
		for instance in usages[candidate]:
			# Create a call node instance
			node = CallNode()
			node.addr = candidate

			# Build the call stack
			stack = callstack(args.elf, instance, ranges, node)

			# Print it
			print_callstack(stack, symbols, imports)
