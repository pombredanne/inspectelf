#!/usr/bin/python2.7

from elftools.elf.elffile import ELFFile
#from shufel import Shufel

from shove import Shove
Shufel = Shove

import itertools
import operator
import argparse
import os
import string
import hashlib
import cfg
import json
from glob import glob
from versions_download import library_name
from ignores import *
from cstrings import clang_parse

def strings(filename, min=4):
	# with open(filename, errors="ignore") as f:  # Python 3.x
	with open(filename, "rb") as f:           # Python 2.x
		result = ""
		for c in f.read():
			if c in string.printable:
				result += c
				continue
			if len(result) >= min and result not in ignore_strings:
				yield result
			result = ""
		if len(result) >= min and result not in ignore_strings:  # catch result at EOF
			yield result

def _process_library(db, proj, version, arch, candidate):
	for f in os.listdir(candidate):
		so = os.path.sep.join((candidate, f))
		print "Processing %s" % (so)

		# Get the file hash
		try:
			with open(so, "rb") as f:
				s = hashlib.sha256()
				s.update(f.read())
				h = s.digest().encode("hex")
		except:
			continue

		# Don't parse the same file again
		if h in db[proj]:
			print "Already in DB."

			# Fix version info as it's usually better the 2nd time
			if len(version) > db[proj][h]["version"]:
				db[proj][h]["version"] = version
				db.sync()

			continue

		# Start parsing every candidate into DB
		db[proj][h] = {
			"hash": h,
			"version": version,
			"arch": arch,
			"strings": [ s for s in strings(so) ]
			}

		# Write to DB so we won't lose any data
		db.sync()

		# Build CFG
		basic_blocks = cfg.build(so)

		if basic_blocks is not None:
			# Get CFG hashes
			db[proj][h]["hashes"] = cfg.hashes(basic_blocks)

			# Get bloomfilter
			db[proj][h]["bloomfilter"] = cfg.bloomfilter(basic_blocks)

		db.sync()

def _process_src(db, proj, version, srcpath):
	# List all files in directory
	files = [y for x in os.walk(srcpath) for y in glob(os.path.join(x[0], '*'))]

	strs = []

	for f in files:
		if os.path.isdir(f):
			continue

		res = clang_parse(f)
		strs += res["strings"] + res["functions"]

	# Add to db
	learn(proj, strs, version)

def build_db(root):
	db = Shufel("file://db")

	# First directory heirarchy holds project names
	for proj in os.listdir(root):
		# Create a new project in db
		if proj not in db:
			db[proj] = { }

		for version in os.listdir(os.path.sep.join((root, proj))):
			for arch in os.listdir(os.path.sep.join((root, proj, version))):
				for candidate in os.listdir(os.path.sep.join((root, proj, version, arch))):
					c = os.path.sep.join((root, proj, version, arch, candidate))

					if arch == "src":
						_process_src(db, proj, version, c)
					else:
						_process_library(db, proj, version, arch, c)
	db.close()

def _set_similarity(library, parameter, target_set):
	highest_ratio = 0
	highest_instance = None

	# No exact match. Look for the most similar
	for h in library:
		instance = library[h]

		# Check if there is any metadata for this parameter
		if parameter not in instance:
			print "No %s for library" % parameter
			continue

		ratio = len(set.intersection(set(instance[parameter]), set(target_set))) / float(len(set.union(set(instance[parameter]), set(target_set))))

		if ratio > highest_ratio:
			highest_ratio = ratio
			highest_instance = instance

	return (highest_instance, highest_ratio)

def _cfg_bloomfilter_similarity(library, bloomfilter):
	highest_count = 0
	highest_instance = None
	popcount = 0

	# No exact match. Look for the most similar
	for h in library:
		count = 0
		instance = library[h]

		if "bloomfilter" not in instance:
			continue

		for b1, b2 in zip(bloomfilter, instance["bloomfilter"]):
			for i in xrange(8):
				# Popcount
				if (b1 & (1 << i)) != 0:
					popcount += 1

				if ((b1 & (1 << i)) == (b2 & (1 << i)) != 0) :
					count += 1

		if count > highest_count:
			highest_count = count
			highest_instance = instance
	if popcount == 0:
		return (None, 0)

	return (highest_instance, float(highest_count) / float(popcount))

def _libname_similarity(elffile, libname):
	db = Shufel("file://db")

	# Start by finding an exact match
	with open(elffile, "rb") as f:
		s = hashlib.sha256()
		s.update(f.read())
		h = s.digest()

	if h in db[libname]:
		# Ratio is 1 because we found an exact match
		return {"libname": libname, "instance": db[libname][h], "ratio": 1}

	similarities = []

	# String similarity
	str_similarity = _set_similarity(db[libname], "strings", [ s for s in strings(elffile) ])

	if str_similarity[0] is not None:
		print libname, str_similarity[1]
		similarities.append(str_similarity)

	# CFG Similarity
	blocks = cfg.build(elffile)

	if blocks is not None:
		# CFG hashes
		hashes = cfg.hashes(blocks)

		result = _set_similarity(db[libname], "hashes", hashes)

		# Get hash similarity
		if result[0] is not None:
			similarities.append(result)

		# CFG Bloomfilter
		bloomfilter = cfg.bloomfilter(blocks)

		result = _cfg_bloomfilter_similarity(db[libname], bloomfilter)

		if result[0] is not None:
			# Get bloomfilter match
			similarities.append(result)

	results = {}

	# Merge similarities according to specific instances
	for sim in similarities:
		if sim[0]["hash"] not in results:
			results[sim[0]["hash"]] = []

		results[sim[0]["hash"]].append(sim)

	highest_ratio = 0
	highest_instnace = None

	# Find what instance is the most similar
	for h in results:
		# Get only the ratio part out of the tuples
		ratio = reduce(lambda x, y: (x[0], x[1] + y[1]), results[h])[1] / float(len(results[h]))

		if ratio > highest_ratio:
			highest_ratio = ratio
			highest_instnace = db[libname][h]

	db.close()

	return {"libname": libname, "instance": highest_instnace, "ratio": highest_ratio}

def similarity(elffile):
	db = Shufel("file://db")

	libname = library_name(os.path.basename(elffile))

	if libname is None:
		raise Exception("Unsupported library name")

	# Library not indexed!
	if libname in db and len(db[libname].keys()) > 0:
		print "Checking with %s" % libname
		return _libname_similarity(elffile, libname)

	highest_ratio = 0
	highest_result = 0

	# Try to find what's the actual library is
	for libname in db.keys():
		print "Checking with %s" % libname
		result = _libname_similarity(elffile, libname)

		if result["ratio"] > highest_ratio:
			highest_ratio = result["ratio"]
			highest_result = result

	db.close()
	return result

def learn(name, strings, version):
	db = Shufel("file://db")

	s = hashlib.sha256()
	s.update("".join(strings))
	h = s.digest()

	db[name][h] = {
			"hash": h,
			"version": version,
			"arch": None,
			"strings": strings
		}

	db.sync()
	db.close()

def _check(_db, strings, name):
	# Find similarity
	instance, ratio = _set_similarity(_db[name], "strings", strings)

	return { "library": instance, "ratio": ratio }

def check(strings, name = None):
	db = Shufel("file://db")

	# Find similarity with a particular library name
	if name is not None:
		sim = _check(strings, name)

		return sim

	# If name is not given, search the entire DB
	highest = None

	for n in db.keys():
		sim = _check(strings, n)

		if (highest is None) or (sim["ratio"] > highest["ratio"]):
			highest = sim

	db.close()
	return highest["library"]

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Inspect libraries and sources delivered by versions_download.py and create a rich database for binary similarity matching")
	parser.add_argument("mode", help = "[scan|identify] to either scan or identify libraries")
	parser.add_argument("path", help = "Path for shared object / objects tree")
	args = parser.parse_args()

	if args.mode == "scan":
		build_db(args.path)
	elif args.mode == "identify":
		result = similarity(args.path)
		if result is not None:
			print "%s v%s (%f)" % (result["libname"], result["instance"]["version"], result["ratio"])
		else:
			print "No matching result"
	else:
		print "Invalid mode"
