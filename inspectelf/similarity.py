#!/usr/bin/python

from elftools.elf.elffile import ELFFile
from shove import Shove
import itertools
import operator
import argparse
import os
import string
import hashlib
import cfg
from versioning import library_name
from ignores import *

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

def build_db(root):
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
						print "Already in DB"
						continue

					# Start parsing every candidate into DB
					db[proj][h] = {
						"hash": h,
						"version": version,
						"arch": arch,
						"strings": set([ s for s in strings(so) ])
						}

					# Build CFG
					basic_blocks = cfg.build(so)

					if basic_blocks is not None:
						# Get CFG hashes
						db[proj][h]["hashes"] = cfg.hashes(basic_blocks)

						# Get bloomfilter
						db[proj][h]["bloomfilter"] = cfg.bloomfilter(basic_blocks)
	db.close()

def _set_similarity(library, parameter, target_set):
	highest_ratio = 0
	highest_instance = None

	# No exact match. Look for the most similar
	for h in library:
		instance = library[h]

		# Check if there is any metadata for this parameter
		if parameter not in instance:
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

	return (highest_instance, float(highest_count) / float(popcount))

def similarity(elffile):
	db = Shove("file://db")

	libname = library_name(os.path.basename(elffile))

	if libname is None:
		raise Exception("Unsupported library name")

	# Library not indexed! 
	if libname not in db:
		return None

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
	similarities.append(_set_similarity(db[libname], "strings", [ s for s in strings(elffile) ]))

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
	highest_instnace = 0

	# Find what instance is the most similar
	for h in results:
		# Get only the ratio part out of the tuples
		ratio = reduce(lambda x, y: (x[0], x[1] + y[1]), results[h])[1] / float(len(results[h]))

		if ratio > highest_ratio:
			highest_ratio = ratio
			highest_instance = db[libname][h]

	db.close()

	return {"libname": libname, "instance": highest_instance, "ratio": highest_ratio}

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("mode", help = "[scan|identify] to either scan or identify libraries")
	parser.add_argument("path", help = "Path for shared object / objects tree")
	args = parser.parse_args()

	if args.mode == "scan":
		build_db(args.path)
	elif args.mode == "identify":
		result = similarity(args.path)
		print "%s v%s (%f)" % (result["libname"], result["instance"]["version"], result["ratio"])
	else:
		print "Invalid mode"