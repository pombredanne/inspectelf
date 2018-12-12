#!/usr/bin/python

import argparse
import pprint
import hashlib
import Levenshtein
import json
from os import path, mkdir, listdir
from elftools.elf.elffile import ELFFile
from capstone import *
from static_cfg import *
from string_cmp import *
from binascii import hexlify

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

def cfg_similarity(elffile):
	# First, calculate file digest
	with open(elffile, "rb") as f:
		s = hashlib.sha256()
		s.update(f.read())
		digest = s.digest().encode("HEX")

	# Next, calculate CFG
	with open(elffile, "rb") as f:
		# Extract symbol CFG
		symbols_cfg = cfg_build(ELFFile(f))

	# Create bloom filter
	bloomfilter = bytearray(BLOOM_FILTER_SIZE)

	# Extract symbol bloom filter
	symbol_bloom = [ cfg_bloom(x) for x in symbols_cfg ]

	# Merge into a larger filter
	for bloom in symbol_bloom:
		for i in xrange(len(bloom)):
			bloomfilter[i] |= bloom[i]

	# Normalize to a bit list
	bloomfilter = [1 if ((bloomfilter[i >> 3] & (1 << (i & 0b111))) != 0) else 0 for i in xrange(len(bloomfilter) * 8)]

	highest_match = {"PERCENTAGE": 0, "ELF-FILENAME": ""}
	result = {}

	# Iterate over all existing filters and find the one matching most
	for filename in listdir("db/"):
		# Only parse bloomfilter files
		if not filename.endswith(".bloomfilter"):
			continue

		with open("db/%s" % filename, "rb") as fp:
			# Load other bloom filter
			otherbloom = json.load(fp)

			hits = 0
			total = 0
			# print filter(lambda x: x == 1, bloomfilter), filename

			for a, b in zip(bloomfilter, otherbloom["BLOOM"]):
				if a == b == 1:
					hits += 1
					total += 1
				elif a == 1 or b == 1:
					total += 1

			# Weirdly processed file. Ignore.
			if total == 0:
				continue

			# Calculate matching percentage
			match = float(hits) / total

			if match > highest_match["PERCENTAGE"]:
				highest_match["PERCENTAGE"] = match
				highest_match["ELF-FILENAME"] = otherbloom["ELF-FILENAME"]

	result["NAME"] = highest_match["ELF-FILENAME"]
	result["RATIO"] = highest_match["PERCENTAGE"]

	# Write bloom filter to file in DB
	with open("db/%s.bloomfilter" % path.basename(elffile), "wb") as fp:
		json.dump({"ELF-HASH": digest, "ELF-FILENAME": path.basename(elffile), "BLOOM": bloomfilter}, fp)

	return result

def levenshtein_similarity(strings):
	highest_ratio = 0
	highest_name = 0
	for filename in listdir("db/"):
		if filename.endswith(".bloomfilter"):
			continue

		with open("db/%s" % filename, "rb") as fp:
			data = json.load(fp)
			orig_cat = str(strings.replace("\x00", ""))
			target_cat = str(data["ELF-STRINGS"].replace("\x00", ""))
			ratio = 1 - (Levenshtein.distance(orig_cat, target_cat)/ float(max(len(orig_cat), len(target_cat))))
			if ratio > highest_ratio:
				highest_ratio = ratio
				highest_name = data["ELF-FILENAME"]
	return {"RATIO": highest_ratio, "NAME": highest_name}

def set_similarity(strings):
	highest_ratio = 0
	highest_name = 0
	for filename in listdir("db/"):
		if filename.endswith(".bloomfilter"):
			continue

		with open("db/%s" % filename, "rb") as fp:
			data = json.load(fp)
			sample_set = set(strings.split("\x00"))
			target_set = set(data["ELF-STRINGS"].split("\x00"))
			ratio = len(set.intersection(sample_set, target_set)) / float(len(set.union(sample_set, target_set)))

			if ratio > highest_ratio:
				highest_ratio = ratio
				highest_name = data["ELF-FILENAME"]
	return {"RATIO": highest_ratio, "NAME": highest_name}

def similarity_engine(elffile):
	# Get the strings
	strings = string_scan(elffile)
	strings = "\x00".join([ "\x00".join(strings[k]) for k in strings ])

	cfg_bloom = cfg_similarity(elffile)

	str_similarity = levenshtein_similarity(strings)

	str_set_similarity = set_similarity(strings)

	similarities = [str_similarity, str_set_similarity, cfg_bloom]

	simdict = {}

	# Find the record with the highest overall similarity
	for sim in similarities:
		if sim["RATIO"] == 0:
			continue

		if sim["NAME"] not in simdict:
			simdict[sim["NAME"]] = {"RATIO": 0, "MEMBERS": 0}
		simdict[sim["NAME"]]["MEMBERS"] += 1
		simdict[sim["NAME"]]["RATIO"] += sim["RATIO"]

	if len(simdict.keys()) == 0:
		return {}

	best = {"RATIO": 0, "MBMERS": 0, "ELF-SIMILAR": ""}
	for s in simdict:
		if best["RATIO"] == 0 or (simdict[s]["RATIO"] / float(simdict[s]["MEMBERS"])) > (best["RATIO"] / float(best["MEMBERS"])):
			best = simdict[s]
			best["ELF-SIMILAR"] = s

	# Fix output for upper layer
	best["ELF-SIMILAR-RATIO"] = best["RATIO"]/float(best["MEMBERS"])
	del best["RATIO"]
	del best["MEMBERS"]

	return best

def inspect(elffile, sysroot = "/", recursive = False, cfg = False, force = False, LIBRARIES = {}, WORK_ARCH = None):
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

		# Check _FORTIFY_SOURCE
		for symbol in dynsym.iter_symbols():
			if symbol.name.startswith("__") and symbol.name.endswith("_chk"):
				MECHANISMS["FORTIFY_SOURCE"] = True

		# ############################# SIMILARITY ENGINES ############################# #
		similarity = similarity_engine(elffile)
		for k in similarity.keys():
			MECHANISMS[k] = similarity[k]

		strings = string_scan(elffile)

		MECHANISMS["ELF-STRINGS"] = "\x00".join([ "\x00".join(strings[k]) for k in strings ])

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

	# Save MECHANISMS to file
	with open("db/%s.json" % path.basename(elffile), "wb") as f:
		json.dump(MECHANISMS, f)

	# Before returning to user, remove bloom filters as it's not interestnig anywhere but here
	for lib in LIBRARIES:
		if "BLOOM" in LIBRARIES[lib]:
			del LIBRARIES[lib]["BLOOM"]

	return LIBRARIES


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
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
