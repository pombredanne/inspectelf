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
	def __init__(self):
		self.init = False
		self.start = None
		self.end = None
		self.instructions = []

def reset_visited_bb(bb):
	bb.visited = False

	for child in bb.branches:
		if child.visited:
			reset_visited_bb(child)

def x64_disasm_bb_flat(data, offset, size):
	# Create a disasm
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True

	bb = BasicBlock()

	BB_ENDS = [X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET, X86_GRP_IRET]

	BB_END = lambda i: filter(lambda g: g in BB_ENDS, i.groups)
	IS_BB_END = lambda i: len(BB_END(i)) > 0

	blocks = []

	# Disasm a bit
	for i in md.disasm(data[offset:offset + size], offset):
		if not bb.init:
			bb.start = i.address

		bb.instructions.append(i.mnemonic)

		if IS_BB_END(i):
			bb.end = i.address
			blocks.append(bb)
			
			# Create a new basic block
			bb = BasicBlock()
			
	return blocks

def x86_disasm_bb_flat(data, offset, size):
	# Create a disasm
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	md.detail = True

	bb = BasicBlock()

	BB_ENDS = [X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET, X86_GRP_IRET]

	BB_END = lambda i: filter(lambda g: g in BB_ENDS, i.groups)
	IS_BB_END = lambda i: len(BB_END(i)) > 0

	blocks = []

	# Disasm a bit
	for i in md.disasm(data[offset:offset + size], offset):
		if not bb.init:
			bb.start = i.address

		bb.instructions.append(i.mnemonic)

		if IS_BB_END(i):
			bb.end = i.address
			blocks.append(bb)
			
			# Create a new basic block
			bb = BasicBlock()
			
	return blocks

def arm_disasm_bb_flat(data, offset, size):
	# Create a disasm
	md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	md.detail = True

	bb = BasicBlock(offset)

	BB_ENDS = [ARM_GRP_JUMP, ARM_GRP_ENDING]

	BB_END = lambda i: filter(lambda g: g in BB_ENDS, i.groups)
	IS_BB_END = lambda i: len(BB_END(i)) > 0

	blocks = []

	# Disasm a bit
	for i in md.disasm(data[offset:offset + size], offset):
		if not bb.init:
			bb.start = i.address

		bb.instructions.append(i.mnemonic)

		if IS_BB_END(i):
			bb.end = i.address
			blocks.append(bb)
			
			# Create a new basic block
			bb = BasicBlock()

	return blocks

def arm64_disasm_bb_flat(data, offset, size):
	# Create a disasm
	md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	md.detail = True

	bb = BasicBlock(offset)

	# Add to visit map to mitigate loops
	visit_map.append(bb)
	BB_ENDS = [ARM64_GRP_JUMP, ARM64_GRP_ENDING]

	BB_END = lambda i: filter(lambda g: g in BB_ENDS, i.groups)
	IS_BB_END = lambda i: len(BB_END(i)) > 0

	blocks = []

	# Disasm a bit
	for i in md.disasm(data[offset:offset + size], offset):
		if not bb.init:
			bb.start = i.address

		bb.instructions.append(i.mnemonic)

		if IS_BB_END(i):
			bb.end = i.address
			blocks.append(bb)
			
			# Create a new basic block
			bb = BasicBlock()
	return blocks

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

ARCH_DISASM = {
		"EM_ARM64": arm64_disasm_bb_flat,
		"EM_ARM": arm_disasm_bb_flat,
		"EM_X86_64": x64_disasm_bb_flat,
		"EM_386": x86_disasm_bb_flat
	}

def _hash_instructions(block):
	# Get flat list of BB hashes
	s = hashlib.sha256()

	for i in block.instructions:
		s.update(i)

	return s.digest()

def hashes(basic_blocks):
	hashes = []
	
	# Get flattened CFG hashes
	if basic_blocks is not None:
		for block in basic_blocks:
			hashes.append(_hash_instructions(block))

	return hashes

def _bloomfilter(block):
	# Create bloom filter to calculate the hash signature for every function
	bloomfilter = bytearray(BLOOM_FILTER_SIZE)

	# Create a list of instruction names across the CFG
	crcs = [crc32(x) for x in block.instructions]

	for crc in crcs:
		# Set the bit offset (truncated to hash size)
		idx = crc % (BLOOM_FILTER_SIZE * 8)
		# print "CRC Idx: %d Bit: %d" % (idx >> 3, 1 << (idx & 0b111))
		bloomfilter[idx >> 3] |= (1 << (idx & 0b111))

	return bloomfilter

def bloomfilter(basic_blocks):
	bfilter = bytearray(BLOOM_FILTER_SIZE)

	# Merge into a larger filter
	for bloom in [ _bloomfilter(block) for block in basic_blocks ]:
		for i in xrange(len(bloom)):
			bfilter[i] |= bloom[i]

	return bfilter

def build(elffile):
	global visit_map

	elf = ELFFile(open(elffile, "rb"))

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

	basic_blocks = []

	text = get_section(elf, ".text")

	basic_blocks = ARCH_DISASM[elf.header.e_machine](data, text.header.sh_offset, text.header.sh_size)

	return basic_blocks