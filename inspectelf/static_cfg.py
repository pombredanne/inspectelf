#!/usr/bin/python

from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86_const import *
from capstone.arm_const import *
from capstone.arm64_const import *
from binascii import crc32, hexlify
import hashlib
import struct
import re

# Reimplementing https://arxiv.org/pdf/1703.00298.pdf
# Large filter size
BLOOM_FILTER_SIZE = 1024 * 4 # 4KByte

def get_section(elf, name):
	for section in elf.iter_sections():
		if name == section.name:
			return section
class BasicBlock:
	def __init__(self, offset):
		self.offset = offset
		self.instructions = []
		self.branches = []
		self.parent = None
		self.end_type = None
		self.visited = False

def reset_visited_bb(bb):
	bb.visited = False

	for child in bb.branches:
		if child.visited:
			reset_visited_bb(child)

visit_map = []

def x64_disasm_bb_flat(data, offset, size):
	# Create a disasm
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True

	root = bb = BasicBlock(offset)

	# Add to visit map to mitigate loops
	visit_map.append(bb)
	BB_ENDS = [X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET, X86_GRP_IRET]

	BB_END = lambda i: filter(lambda g: g in BB_ENDS, i.groups)
	IS_BB_END = lambda i: len(BB_END(i)) > 0

	# Disasm a bit
	for i in md.disasm(data[offset:offset + size], offset):
		# print dir(i)
		bb.instructions.append(i.mnemonic)
		if IS_BB_END(i):
			prev = bb
			bb = BasicBlock(i.address)
			prev.branches.append(bb)
	return root

def arm_disasm_bb_flat(data, offset, size):
	# Create a disasm
	md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	md.detail = True

	root = bb = BasicBlock(offset)

	# Add to visit map to mitigate loops
	visit_map.append(bb)
	BB_ENDS = [ARM_GRP_JUMP, ARM_GRP_ENDING]

	BB_END = lambda i: filter(lambda g: g in BB_ENDS, i.groups)
	IS_BB_END = lambda i: len(BB_END(i)) > 0

	# Disasm a bit
	for i in md.disasm(data[offset:offset + size], offset):
		# print dir(i)
		bb.instructions.append(i.mnemonic)
		if IS_BB_END(i):
			prev = bb
			bb = BasicBlock(i.address)
			prev.branches.append(bb)
	return root

def arm64_disasm_bb_flat(data, offset, size):
	# Create a disasm
	md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	md.detail = True

	root = bb = BasicBlock(offset)

	# Add to visit map to mitigate loops
	visit_map.append(bb)
	BB_ENDS = [ARM64_GRP_JUMP, ARM64_GRP_ENDING]

	BB_END = lambda i: filter(lambda g: g in BB_ENDS, i.groups)
	IS_BB_END = lambda i: len(BB_END(i)) > 0

	# Disasm a bit
	for i in md.disasm(data[offset:offset + size], offset):
		# print dir(i)
		bb.instructions.append(i.mnemonic)
		if IS_BB_END(i):
			prev = bb
			bb = BasicBlock(i.address)
			prev.branches.append(bb)
	return root

def x64_disasm_bb(data, offset):
	global visted_bb

	# Create a disasm
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True

	# Make sure we're not looping indefinately
	for prev in visit_map:
		if prev.offset == offset:
			# print "Already was here (0x%x)" % offset
			return prev

	bb = BasicBlock(offset)

	# Add to visit map to mitigate loops
	visit_map.append(bb)
	BB_ENDS = [X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET, X86_GRP_IRET]

	BB_END = lambda i: filter(lambda g: g in BB_ENDS, i.groups)
	IS_BB_END = lambda i: len(BB_END(i)) > 0

	# Disasm a bit
	for i in md.disasm(data[offset:], offset):
		bb.instructions.append(i)

		# print i.insn_name(), "\t", i.op_str, "\t\t", i.groups

		# If this is the end of a basic block, branch to the new ones and return.
		if IS_BB_END(i):
			# Add this basic block to the function
			end_type = BB_END(i)[0]
			if end_type == X86_GRP_JUMP:
				if "ptr" in i.op_str:
					# Cannot handle pointers statically ATM. Ignore.
					continue

				# If it's a memory relative jump (RIP + ) Try getting it from offset
				hit = re.search("\[rip \+ (0x[0-9a-f]+)\]", i.op_str)

				if hit is not None and len(hit.groups()) > 0:
					# TBD. This is a runtime calculated branch. Can't do it (right now)
					continue

					data_offset = i.address + len(i.bytes) + int(hit.groups()[0], 16) - 0x5748

					# print hex(data_offset), hex(i.address), hex(int(hit.groups()[0], 16)), hex(len(data))
					# print len(data[data_offset : data_offset + 8])
					jmp_offset = struct.unpack("Q", data[data_offset : data_offset + 8])
				else:
					try:
						# Calculate jump offset
						jmp_offset = int(i.op_str, 16)
					except:
						# Prolly not an offset
						continue

				# Declare end type
				bb.end_type = "JMP"
				# print "JUMPING to %x" % jmp_offset

				# Start a new basic block
				bb.branches.append(x64_disasm_bb(data, jmp_offset))

				# If it is a hard JMP, we SHOULDN'T continue parsing next linear instructions
				# Otherwise, continue branching the following instruction linearily
				if i.insn_name() != "jmp":
					bb.branches.append(x64_disasm_bb(data, i.address + len(i.bytes)))

			elif end_type == X86_GRP_CALL:
				# Calculate call offset
				if "ptr" in i.op_str:
					# Can't handle pointers statically. Ignore ATM.
					continue

				try:
					call_offset = int(i.op_str, 16)
				except:
					# Prolly not an offset
					continue

				bb.end_type = "CALL"
				# print "CALLING %x" % call_offset

				# Disassemble one branch
				bb.branches.append(x64_disasm_bb(data, call_offset))

				# Disassemble the other
				bb.branches.append(x64_disasm_bb(data, i.address + len(i.bytes)))

			elif end_type == X86_GRP_RET or end_type == X86_GRP_IRET:
				# print "RETURNING"
				bb.end_type = "RET"
				# Return to previous layer

			return bb

	return bb

def cfg_flat_instructions(bb):
	inst = []

	while len(bb.branches) > 0:
		inst += bb.instructions
		bb = bb.branches[0]
	inst += bb.instructions

	return inst

	# Avoid loops
	if bb.visited:
		return inst

	bb.visited = True
	for i in bb.instructions:
		inst.append(i)

	# Merge instructions
	for child in bb.branches:
		inst += cfg_flat_instructions(child)

	return inst

ARCH_DISASM = {
		"EM_ARM64": arm64_disasm_bb_flat,
		"EM_ARM": arm_disasm_bb_flat,
		"EM_X86_64": x64_disasm_bb_flat
	}

def cfg_build(elf):
	global visit_map

	# Validate architecture support
	if not elf.header.e_machine in ARCH_DISASM:
		print "No supported arch"
		return None

	# print "Building CFG!!!"
	visit_map = []

	if type(elf) == str:
		elf = ELFFile(open(elf, "rb"))

	dynsym = get_section(elf, ".dynsym")

	relaplt = get_section(elf, ".rela.plt")
	elf.stream.seek(0)
	data = elf.stream.read()

	symbols_cfg = []

	text = get_section(elf, ".text")

	symbols_cfg = [ARCH_DISASM[elf.header.e_machine](data, text.header.sh_offset, text.header.sh_size)]

	# print "Symbol CFG: %d" % len(symbols_cfg)
	return symbols_cfg

	# ### Building a tree takes too long for some reason. Build basic blocks linearily instead ### #

	# Build basic blocks tree
	for symbol in dynsym.iter_symbols():
		if symbol.entry.st_value == 0 or len(symbol.name) == 0:
			continue

		# print "=" * 32 + " " + symbol.name + " " + "=" * 32

		# Already validated arch support
		symbols_cfg.append(ARCH_DISASM[elf.header.e_machine](data, symbol.entry.st_value))

	return symbols_cfg

def cfg_bloom(cfg_root):
	# Create bloom filter to calculate the hash signature for every function
	bloomfilter = bytearray(BLOOM_FILTER_SIZE)

	reset_visited_bb(cfg_root)

	# Create a list of instruction names across the CFG
	hash_raw_data = cfg_flat_instructions(cfg_root)

	crcs = [crc32(x) for x in hash_raw_data]

	# print crcs
	# print [hex(x) for x in crcs]

	for crc in crcs:
		# Set the bit offset (truncated to hash size)
		idx = crc % (BLOOM_FILTER_SIZE * 8)
		# print "CRC Idx: %d Bit: %d" % (idx >> 3, 1 << (idx & 0b111))
		bloomfilter[idx >> 3] |= (1 << (idx & 0b111))

	return bloomfilter

def cfg_flatten_bb(cfg_root):
	bbs = []

	# As we're not building a tree ATM (Too time-expensive) flatten this recursion as well
	while len(cfg_root.branches) > 0:
		# Hash the instructions
		s = hashlib.sha1()
		for i in cfg_root.instructions:
			s.update(i)
		bbs.append(s.digest().encode("HEX"))

		cfg_root = cfg_root.branches[0]
	# Hash the last
	s = hashlib.sha1()
	for i in cfg_root.instructions:
		s.update(i)
	bbs.append(s.digest().encode("HEX"))

	return bbs

	# Avoid loops
	if cfg_root.visited:
		return bbs

	# Mark this node as visited
	cfg_root.visited = True

	# Hash the instructions
	s = hashlib.sha256()
	for i in cfg_root.instructions:
		s.update(i)
	bbs.append(s.digest().encode("HEX"))

	for b in cfg_root.branches:
		bbs += cfg_flatten_bb(b)

	return bbs

def cfg_hashes(cfg_root):
	# Reset path markers
	reset_visited_bb(cfg_root)

	# Get flat list of BB hashes
	return cfg_flatten_bb(cfg_root)
