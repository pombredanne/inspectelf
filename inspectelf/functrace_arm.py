#!/usr/bin/python
import re
from elftools.elf.elffile import ELFFile
from capstone import *

def find_functions_arm(section, symbols, found_funcs, terminating = []):
	# print [hex(x) for x in terminating]
	md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

	md.skipdata = True

	# Start with first address of section
	addresses = [section.header.sh_addr]

	functions = {}

	# Start with all the given symbols
	expected_functions = [ x for x in symbols ]

	branches = [
			{"mnemonic": "b", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "bls", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "bne", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "bcs", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "beq", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "bhi", "arg": "#(0x[0-9a-f]+)"},
			{"mnemonic": "bcc", "arg": "#(0x[0-9a-f]+)"},
	 		{"mnemonic": "cbz", "arg": "x[0-9]+, #(0x[0-9a-f]+)"},
	 		{"mnemonic": "cbnz", "arg": "x[0-9]+, #(0x[0-9a-f]+)"},
	 		{"mnemonic": "tbz", "arg": "[rw][0-9], #x[0-9]+, #(0x[0-9a-f]+)"}
	 	]

	calls = [
			{"mnemonic": "bl", "arg": "#(0x[0-9a-f]+)"}
		]
	nops = [
			bytes("\x00\x00\x00\x00"),
			bytes("\x1f\x20\x03\xd5"),
			bytes("\xf8\x0e\x02\x00"),
			bytes("\xc8\x04\x01\x00"),
			bytes("\x64\x00\x00\x00"),
			bytes("\x3c\x04\x01\x00")
		]

	# print "Section address: 0x%x" % section.header.sh_addr

	for i in md.disasm(section.data(), section.header.sh_addr):
		# In ARM padding comes at the end of functions. Make it a marker.
		skip_nop = False
		for nop in nops:
			# if i.bytes == nop and len(addresses) > 0:
			if i.bytes[-1] == 0 and len(addresses) > 0 and i.address > addresses[-1]:
				# print "NOP", [ hex(x) for x in i.bytes ], i.mnemonic, i.op_str

				# Don't include the NOP
				functions[addresses[0]] = i.address - addresses[0]

				addresses = []

				skip_nop = True
				break
			elif i.bytes[-1] == 0:
				skip_nop = True

		if skip_nop:
			continue

		if len(addresses) == 0:
			addresses.append(i.address)

		# Is this the end of the function?
		# Marked as a return clause that has no referenced addresses further ahead
		# in the assembly
		if i.mnemonic == "bx" and i.op_str == "lr" and i.address >= addresses[-1]:
			if addresses[0] in expected_functions:
				#print "Found expected function: 0x%x" % addresses[0]

				expected_functions.remove(addresses[0])

			# Found a function end.
			functions[addresses[0]] = i.address - addresses[0] + 4

			# print "Found function (RET): 0x%x (%d)" % (addresses[0], functions[addresses[0]])

			# Start looking at a new function
			addresses = [i.address + 4]

			continue
		elif i.mnemonic == "bx":
			pass
			# print "RET at 0x%x Farthest ptr: 0x%x" % (i.address, addresses[-1])

		for c in calls:
			if i.mnemonic == c["mnemonic"]:
				m = re.match(c["arg"], i.op_str)

				if m is None:
					continue

				nextaddr = int(m.groups()[0], 16)

				if nextaddr in terminating and i.address >= addresses[-1]:
					if addresses[0] in expected_functions:
						#print "Found expected function: 0x%x" % addresses[0]

						expected_functions.remove(addresses[0])

					# Found a function end.
					functions[addresses[0]] = i.address - addresses[0] + 4

					# print "Found function (TERMINATING CALL): 0x%x (%d)" % (addresses[0], functions[addresses[0]])

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
				# if nextaddr in found_funcs:
				#	break

				# Too long a jump??
				if nextaddr - i.address > 4096 * 2:
					break

				# Check if it's the furthest branch and is pointing back inside the function
				# Only "b" is considered terminating!!
				if ((i.address >= addresses[-1]) and ((i.address >= nextaddr) or (nextaddr in found_funcs)) and (i.mnemonic == "b")) or (nextaddr in terminating):
					if addresses[0] in expected_functions:
						# print "Found expected function: 0x%x" % addresses[0]

						expected_functions.remove(addresses[0])

					# Found a function end.
					functions[addresses[0]] = i.address - addresses[0] + 4

					# print "Found function (BACK JMP): 0x%x (%d)" % (addresses[0], functions[addresses[0]])

					# Start looking at a new function
					addresses = [i.address + 4]
				elif nextaddr not in found_funcs:
				# else:
					# print "Next addr: 0x%x End addr: 0x%x" % (nextaddr, addresses[-1])
					addresses.append(nextaddr)
					addresses.sort()
				break

		# If after all the above logic we're still the head of the function, update it.
		if i.address > addresses[-1]:
				# print "0x%x > 0x%x" % (i.address, addresses[-1])
				# addresses.remove(addresses[-1])
				addresses.append(i.address)
		# addresses.sort()
		# if addresses[-1] < i.address:
			# addresses[-1] = i.address


	offsets = list(functions.keys())
	offsets.sort()

	for x in functions:
		if x in expected_functions:
			expected_functions.remove(x)

	for x in found_funcs:
		if x in expected_functions:
			expected_functions.remove(x)

	expected_functions.sort()

	# Merge expected functions with found functions
	for expected in expected_functions:
		for i in xrange(len(offsets) - 1):
			off0 = offsets[i]
			off1 = offsets[i + 1]
			# Find the exact spot to place the expected symbol (either from detected CALL or from a symbol)
			# Make sure the offset is indeed in found functions (as for some weird reasons some aren't (??))
			# And make sure we don't have some false positives with symbols that point 8 bytes prior to actual function start
			if off1 > expected > off0  and off0 in functions and expected - off0 < functions[off0]:
				prev = functions[off0]
				functions[off0] = expected - off0

				# Add the new function
				functions[expected] = prev - functions[off0]

				# print "Prev: 0x%x (%d) New: 0x%x (%d) Next: 0x%x (%d)" % (off0, functions[off0], expected, functions[expected], off1, functions[off1])

				offsets.append(expected)
				offsets.sort()

				break

	# print "Functions:", [ (hex(x), functions[x]) for x in functions ]
	# print "Expected (unfound) functions:", [ hex(x) for x in expected_functions ]
	return functions
