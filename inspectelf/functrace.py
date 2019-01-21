#!/usr/bin/python

import argparse
import os
import re
from elftools.elf.elffile import ELFFile
from capstone import *

from functrace_arm import find_functions_arm
from functrace_aarch64 import find_functions_aarch64

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
		# if plt.header.sh_entsize == 0:
		plt.header.sh_entsize = 12
		startoff = 0x14
		idx = 0

	relocs = {}

	for reloc in rela_plt.iter_relocations():
		r = {
				"name": symtab.get_symbol(reloc.entry.r_info_sym).name,
				"offset": plt.header.sh_addr + startoff + plt.header.sh_entsize * idx,
				"reloc": reloc,
				"index": idx
			}

		# print "%s@plt = 0x%x" % (r["name"], r["offset"])
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
				# print hex(i["offset"]), "(%s)\t" % hex(i["reloc"].entry.r_info_sym), i["name"]
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

	# Create a placeholder for all usages
	for offset in addresses:
		usages[offset] = []

	#for i in md.disasm(text.data(), elf.header.e_entry):
	for i in md.disasm(text.data(), text.header.sh_addr):
		if i.mnemonic == mnemonic:
			# Try and match
			m = re.match(pattern, i.op_str)
			if m is None:
				continue

			addr = int(m.groups()[0], 16)

			# If referencing to something not in usages, discard it.
			if addr not in usages:
				continue

			usages[addr].append(i.address)

	# for u in usages:
	# 	if len(usages[u]) == 0:
	#		print "Found no usages for address 0x%x" % u

	return usages


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

	# Add symbols to the party
	symbols = find_symbols(elffile)

	if elf.header.e_machine == "EM_AARCH64":
		return find_functions_aarch64(text, symbols, found_funcs, terminating_funcs)
	elif elf.header.e_machine == "EM_ARM":
		return find_functions_arm(text, symbols, found_funcs, terminating_funcs)

def find_symbols(elffile):
	elf = ELFFile(open(elffile, "rb"))

	symtab = elf.get_section_by_name(".symtab")

	if symtab is None:
		# raise Exception("No .symtab section found")
		return {}

	symbols = {}

	for s in symtab.iter_symbols():
		# print s.entry
		if s.entry.st_value == 0 or s.entry.st_info.type != "STT_FUNC":
			continue
		symbols[s.entry.st_value] = s.name

	return symbols

def find_addr_in_range(addr, ranges):
	try:
		stage = len(ranges)
		i = stage / 2

		while stage > 0:
			stage /= 2
			# print "i = %d stage: %d 0x%x < 0x%x < 0x%x" % (i, stage, ranges[i][0], addr, ranges[i][1])
			if ranges[i][1] < addr:
				i += stage
			elif addr < ranges[i][0]:
				i -= stage
			else:
				return ranges[i][0]

		if ranges[i - 1][0] <= addr <= ranges[i - 1][1]:
			return ranges[i - 1][0]

		if ranges[i + 1][0] <= addr <= ranges[i + 1][1]:
			return ranges[i + 1][0]
	except:
		pass

	# Didn't find any range? Weird...
	r = filter(lambda r: r[0] < addr < r[1], ranges)
	# print ["0x%x - 0x%x" % (start, end) for start, end in r]
	if len(r) != 1:
		return None
	else:
		return r[0][0]

def callstack(elffile, addr, function_ranges, child, depth = 0, loop_map = None):
	if loop_map is None:
		loop_map = []

	calling_function = find_addr_in_range(addr, function_ranges)

	if calling_function is None:
		print "No calling function for address 0x%x" % addr
		return child

	node = CallNode()
	node.addr = calling_function

	if addr in loop_map:
		return child
	else:
		loop_map.append(addr)

	child.usages[addr] = node

		# print "Looking for usages for 0x%x" % calling_function
	usages = find_usages(elffile, {calling_function: {"name": ""}})
	for func in usages:
		for u in usages[func]:
			callstack(elffile, u, function_ranges, node, depth + 1, loop_map)

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

def json_callstack(node, symbols, imports, depth = 0, callpoint = None):
	n = {}

	if callpoint is not None:
		n["callpoint"] = callpoint

	if node.addr in symbols:
		n["name"] = symbols[node.addr]
		n["address"] = node.addr
	elif node.addr in imports:
		n["name"] = imports[node.addr]["name"]
		n["address"] = node.addr
	else:
		n["name"] = "unnamed"
		n["address"] = node.addr

	n["friendly"] = "%s@0x%x" % (n["name"], n["address"])
	n["usages"] = []

	for u in node.usages:
		n["usages"].append(json_callstack(node.usages[u], symbols, imports, depth + 1, u))

	return n

def fix_overlapping_ranges(functions):
	sorted_starts = list(functions.keys())
	sorted_starts.sort()
	ranges = []
	skip = 0
	for s in sorted_starts:
		if skip > 0:
			skip -= 1
			continue

		e = s + functions[s]
		for s2 in sorted_starts:
			if s < s2 < e:
				skip += 1
				if e < (s2 + functions[s2]):
					e = s2 + functions[s2]
			elif e <= s2:
				break
		ranges.append((s, e))
	return ranges

def traces(elffile, funcnames):
	print "Finding functions..."

	# Find all functions within the ELF object
	functions = find_functions(elffile)

	ranges = fix_overlapping_ranges(functions)

	print ["0x%x - 0x%x" % (start, end) for start, end in ranges]

	print "Looking for imports..."

	# Hold all imports + symbols
	imports = import_funcs(elffile)

	# Find all imports of given pattern
	selected_imports = import_match(elffile, funcnames)

	print "Finding usages..."

	# Find all the usages of the following functions
	usages = find_usages(elffile, selected_imports)

	symbols = find_symbols(elffile)

	res = {}

	for candidate in usages:
		res[candidate] = []

		for instance in usages[candidate]:
			# Create a call node instance
			node = CallNode()
			node.addr = candidate

			# Build the call stack
			stack = callstack(elffile, instance, ranges, node)

			r = json_callstack(stack, symbols, imports)
			res[r["friendly"]] = r

			# Print it
			print_callstack(stack, symbols, imports)

	return res

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Inspect ELF Files to discover functions (named and unnamed) and create a function trace graph")
	parser.add_argument("elf", help = "ELF File")

	# Parse arguments
	args = parser.parse_args()

	traces(args.elf, ["sha", "aes", "des", "md5", "memcpy", "memset"])
