#!/usr/bin/python

from elftools.elf.elffile import ELFFile
from shove import Shove
import itertools
import operator
import argparse
import os
import string
import hashlib
from versioning import library_name

ignore_strings = [
	".ARM.attributes",
	".bss",
	".comment",
	".data",
	".data.rel.ro",
	".divsi3_skip_div0_test",
	".dynamic",
	".dynstr",
	".dynsym",
	".eh_frame",
	".fini",
	".fini_array",
	".gnu.attributes",
	".gnu.hash",
	".gnu.version",
	".gnu.version_r",
	".hash",
	".init",
	".init_array",
	".mdebug.abi32",
	".MIPS.abiflags",
	".note.GNU-stack",
	".note.gnu.build-id",
	".reginfo",
	".rel.data.rel.local",
	".rel.dyn",
	".rel.pdr",
	".rel.plt",
	".rel.text",
	".rela.data.rel.local",
	".rela.eh_frame",
	".rela.text",
	".rodata",
	".sdata",
	".shstrtab",
	".strtab",
	".symtab",
	".text",
	".udivsi3_skip_div0_test",
	"__adddf3",
	"__aeabi_cdcmpeq",
	"__aeabi_cdcmple",
	"__aeabi_cdrcmple",
	"__aeabi_d2iz",
	"__aeabi_dadd",
	"__aeabi_dcmpeq",
	"__aeabi_dcmpge",
	"__aeabi_dcmpgt",
	"__aeabi_dcmple",
	"__aeabi_dcmplt",
	"__aeabi_ddiv",
	"__aeabi_dmul",
	"__aeabi_drsub",
	"__aeabi_dsub",
	"__aeabi_f2d",
	"__aeabi_i2d",
	"__aeabi_idiv",
	"__aeabi_idiv0",
	"__aeabi_idivmod",
	"__aeabi_l2d",
	"__aeabi_ldiv0",
	"__aeabi_ui2d",
	"__aeabi_uidiv",
	"__aeabi_uidivmod",
	"__aeabi_ul2d",
	"__bss_end__",
	"__bss_start",
	"__bss_start__",
	"__clzsi2",
	"__cmpdf2",
	"__ctzsi2",
	"__cxa_finalize",
	"__cxa_finalize@@GLIBC_2.4",
	"__divdf3",
	"__divsi3",
	"__do_global_dtors_aux",
	"__do_global_dtors_aux_fini_array_entry",
	"__dso_handle",
	"__end__",
	"__eqdf2",
	"__extendsfdf2",
	"__fixdfsi",
	"__floatdidf",
	"__floatsidf",
	"__floatundidf",
	"__floatunsidf",
	"__frame_dummy_init_array_entry",
	"__FRAME_END__",
	"__gedf2",
	"__gmon_start__",
	"__gtdf2",
	"__JCR_END__",
	"__JCR_LIST__",
	"__ledf2",
	"__ltdf2",
	"__muldf3",
	"__nedf2",
	"__subdf3",
	"__TMC_END__",
	"__udivsi3",
	"_bss_end__",
	"_DYNAMIC",
	"_edata",
	"_fbss",
	"_fdata",
	"_fini",
	"_ftext",
	"_GLOBAL_OFFSET_TABLE_",
	"_gp_disp",
	"_init",
	"_ITM_deregisterTMCloneTable",
	"_ITM_registerTMCloneTable",
	"_Jv_RegisterClasses",
	"deregister_tm_clones",
	"GLIBC_2.4",
	"register_tm_clones",
]

def strings(filename, min=4):
	# with open(filename, errors="ignore") as f:  # Python 3.x
	with open(filename, "rb") as f:           # Python 2.x
		result = ""
		for c in f.read():
			if c in string.printable:
				result += c
				continue
			if len(result) >= min:
				yield result
			result = ""
		if len(result) >= min:  # catch result at EOF
			yield result

# Retrieves readable strings from a (section of an ELF) file
def read_strings(f, section = None):
	i = 0
	inString = False
	curStr = bytearray('')
	try:
		f = open(f, 'rb')
		if section is not None:
			offset = section.header.sh_offset
			size = section.header.sh_size
			f.seek(offset)
		byte = f.read(1)
		while byte != "" and f.tell() < offset + size:
			# Between space and tilde (i.e printable and non-special)
			if ord(byte) >= 0x20 and ord(byte) < 0x7F:
				if not inString:
					# Skip whitespace at start of strings?
					#while byte in string.whitespace:
					#   byte = f.read(1)

					# We're in a new string
					inString = True

					# Yield the latest string
					if str(curStr) not in ignore_strings:
						yield str(curStr)

					curStr = bytearray('')

				curStr.append(byte)
			else:
				inString = False

			byte = f.read(1)

		# Return the final string, if needed
		if inString and str(curStr) not in ignore_strings:
			yield str(curStr)

		f.close()
	except IOError:
		pass

# Returns strings of appropriate minimum length, sorted and unique
def get_strings(f, section, minLength=5):
	# fast generator-friendly version of uniq+sort
	# from http://stackoverflow.com/questions/2931672/
	def sort_uniq(sequence):
		return itertools.imap(
			operator.itemgetter(0),
			itertools.groupby(sorted(sequence)))

	return sort_uniq(itertools.ifilter(lambda s: len(s) >= minLength,
					   read_strings(f, section)))

def string_scan(elffile):
	strs = {}

	with open(elffile, "rb") as fp:
		elf = ELFFile(fp)
		sections = ('.dynstr', '.rodata', '.data', '.strtab')

		for section in elf.iter_sections():
			if section.name in sections:
				strs[section.name] = list(get_strings(elffile, section))

	return strs

def build_db(db, root):
	db = Shove("file://db")

	# First directory heirarchy holds project names
	for proj in os.listdir(root):
		# Create a new project in db
		if proj not in db:
			db[proj] = { }

		for version in os.listdir(os.path.sep.join((root, proj))):
			for arch in os.listdir(os.path.sep.join((root, proj, version))):
				for candidate in os.listdir(os.path.sep.join((root, proj, version, arch))):
					c = os.path.sep.join((root, proj, version, arch, candidate))
					so = os.path.sep.join((c, os.listdir(c)[0]))
					print "Processing %s" % (so)

					# Get the file hash
					with open(so, "rb") as f:
						s = hashlib.sha256()
						s.update(f.read())
						h = s.digest()

					# Don't parse the same file again
					if h in db[proj]:
						continue

					# Start parsing every candidate into DB
					db[proj][h] = {
						"version": version,
						"arch": arch,
						"strings": set([ s for s in strings(so) ])
						}
	db.close()

def similarity(elffile):
	db = Shove("file://db")

	libname = library_name(elffile)

	if libname is None:
		raise Exception("Unsupported library name")

	# Library not indexed! 
	if libname not in db:
		return None

	# Start by finding an exact match
	with open(elffile, "rb") as f:
		s = hashlib.sha256()
		s.update(r.read())
		h = s.digest()

	if h in db[libname]:
		return db[libname][h]

	highest_ratio = 0
	highest_instance = 0

	# Get all its strings
	target_set = set([ s for s in strings(elffile) ])

	# No exact match. Look for the most similar
	for h in db[libname]:
		instance = db[libname][h]

		ratio = len(set.intersection(instance["strings"], target_set)) / float(len(set.union(instance["strings"], target_set)))

		if ratio > highest_ratio:
			highest_ratio = ratio
			highest_instance = instance

	db.close()

	return {"instance": highest_instance, "ratio": highest_ratio}



if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("path", help = "Path for shared objects directory tree")
	args = parser.parse_args()
	build_db(args.path)