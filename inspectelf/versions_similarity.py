#!/usr/bin/python2.7

from elftools.elf.elffile import ELFFile
from shufel import Shufel

# from shove import Shove
# Shufel = Shove

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
import time
from console_progressbar import ProgressBar

import redis
from redisdb import *

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
		if (version in db[proj]["versions"]) and (h in db[proj]["versions"][version]):
			continue

		if version not in db[proj]["versions"]:
			db[proj]["versions"][version] = []

		db[proj]["versions"][version].append(h)

		# Start parsing every candidate into DB
		db[proj]["hashes"][h] = [ s for s in strings(so) ]

		return

		# ### TODO: NEED TO RETHINK PLAUSABILITY OF BINARY BASED SIMILARITY ### #

		# Build CFG
		basic_blocks = cfg.build(so)

		if basic_blocks is not None:
			# Get CFG hashes
			db[proj]["hashes"][h]["hashes"] = cfg.hashes(basic_blocks)

			# Get bloomfilter
			db[proj]["hashes"][h]["bloomfilter"] = cfg.bloomfilter(basic_blocks)

		db.sync()

def _process_src(_db, proj, version, srcpath):
	# Don't parse again the same version
	if version in _db[proj]["versions"].keys():
		print "Source %s v%s already parsed" % (proj, version)
		return

	print "Processing %s v%s..." % (proj, version)

	# List all files in directory
	files = [y for x in os.walk(srcpath) for y in glob(os.path.join(x[0], '*'))]

	strs = set()

	c = 0

	pb = ProgressBar(total=100, suffix="%s v%s" % (proj, version), decimals=3, length=100, fill='X', zfill='-')
	pb.print_progress_bar(0)

	for f in files:
		c += 1
		pb.print_progress_bar(100 * float(c)/len(files))

		if os.path.isdir(f):
			continue

		if not os.path.exists(f):
			continue

		with open(f, "rb") as fp:
			sha = hashlib.sha256()
			sha.update(fp.read())
			hash = sha.digest().encode("HEX")

		#print "Trying %s" % f

		if hash in _db[proj]["srcs"]:
			pass
			#print "%s already indexed" % hash
		else:
			# print "Building %s" % f
			try:
				res = clang_parse(f)

				s = set(res["strings"] + res["functions"])
			except Exception, e:
				print "Error in building source file %s" % f
				continue

			_db[proj]["srcs"][hash] = s

		strs = strs.union(_db[proj]["srcs"][hash])

		# if c == 5:
		#	break

	# Add to db
	learn(_db, proj, strs, version)

def build_db(root):
	db = redisdb(redis.Redis(host = "localhost", port = 6379))

	# First directory heirarchy holds project names
	for proj in os.listdir(root):
		# Create a new project in db
		if proj not in db.keys():
			db[proj] = {}
			db[proj]["hashes"] = {}
			db[proj]["srcs"] = {}
			db[proj]["versions"] = {}

		for version in os.listdir(os.path.sep.join((root, proj))):
			for arch in os.listdir(os.path.sep.join((root, proj, version))):
				for candidate in os.listdir(os.path.sep.join((root, proj, version, arch))):
					c = os.path.sep.join((root, proj, version, arch, candidate))

					if arch == "src":
						_process_src(db, proj, version, c)
					else:
						_process_library(db, proj, version, arch, c)

def _set_similarity(library, parameter, target_set):
	highest_ratio = 0
	highest_instance = None

	# No exact match. Look for the most similar
	for h in library:
		instance = library[h]

		# Check if there is any metadata for this parameter
		if parameter not in instance:
			# print "No %s for library" % parameter
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

def _hash_to_version(library, h):
	for v in library["versions"]:
		for hv in library["versions"][v]:
			if hv == h:
				return v

	return None

def _string_similarity(library, target_set):
	highest_ratio = 0
	highest_instance = None

	for h in library["hashes"].keys():
		version_set = library["hashes"][h]

		# TODO: Decide which one of these two calculations is better.
		# The first one yields much lower percentages as the strings gathered from sources
		# will always be larger in numbers than those gathered from the binary itself.
		# Comparing according to lower numbers may yield inaccurate false positives with
		# close versions...
		ratio = len(set.intersection(version_set, target_set)) / float(len(set.union(version_set, target_set)))

		# ratio = len(set.intersection(version_set, target_set)) / float(len(target_set))
		print "%s = %f" % (_hash_to_version(library, h), ratio)

		if ratio > highest_ratio:
			highest_ratio = ratio
			highest_instance = h

	highest_version = _hash_to_version(library, highest_instance)

	return {"version": highest_version, "ratio": highest_ratio}

def _libname_similarity(db, elffile, libname):
	# Start by finding an exact match
	with open(elffile, "rb") as f:
		s = hashlib.sha256()
		s.update(f.read())
		h = s.digest().encode("hex")

	if h in db[libname]["hashes"]:
		# Ratio is 1 because we found an exact match
		return {"libname": libname, "instance": db[libname]["hashes"][h], "ratio": 1}

	# String similarity
	str_similarity = _string_similarity(db[libname], set([ s for s in strings(elffile) ]))

	return {"libname": libname, "version": str_similarity["version"], "ratio": str_similarity["ratio"]}

	if str_similarity[0] is not None:
		print libname, str_similarity[1]
		similarities.append(str_similarity)

	# CFG Similarity
	blocks = cfg.build(elffile)

	if blocks is not None:
		# CFG hashes
		hashes = cfg.hashes(blocks)

		result = _set_similarity(db[libname]["hashes"], "hashes", hashes)

		# Get hash similarity
		if result[0] is not None:
			similarities.append(result)

		# CFG Bloomfilter
		bloomfilter = cfg.bloomfilter(blocks)

		result = _cfg_bloomfilter_similarity(db[libname]["hashes"], bloomfilter)

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
			highest_instnace = db[libname]["hashes"][h]

	# db.close()

	return {"libname": libname, "instance": highest_instnace, "ratio": highest_ratio}

def similarity(elffile):
	db = redisdb(redis.Redis(host = "localhost", port = 6379))

	libname = library_name(os.path.basename(elffile))

	if libname is None:
		raise Exception("Unsupported library name")

	# Library not indexed!
	if libname in db and len(db[libname].keys()) > 0:
		print "Checking with %s" % libname
		return _libname_similarity(db, elffile, libname)

	highest_ratio = 0
	highest_result = 0

	# Try to find what's the actual library is
	for libname in db:
		print "Checking with %s" % libname
		result = _libname_similarity(db, elffile, libname)

		if result["ratio"] > highest_ratio:
			highest_ratio = result["ratio"]
			highest_result = result

	return result

def learn(_db, proj, strings, version):

	s = hashlib.sha256()
	s.update("".join(strings))
	h = s.digest().encode("HEX")

	print "Hashing %d strings" % len(strings)
	print "Hash: %s" % h

	s = set(strings)

	print "Set size: %d" % len(s)

	_db[proj]["hashes"][h] = s

	if version not in _db[proj]["versions"].keys():
		_db[proj]["versions"][version] = []

	_db[proj]["versions"][version].append(h)

def _check(_db, strings, name):
	# Find similarity
	instance, ratio = _set_similarity(_db[name]["hashes"], "strings", strings)

	return { "library": instance, "ratio": ratio }

def check(strings, name = None):
	db = redisdb(redis.Redis(host = "localhost", port = 6379))

	# Find similarity with a particular library name
	if name is not None:
		sim = _check(db, strings, name)

		return sim

	# If name is not given, search the entire DB
	highest = None

	for n in db.keys():
		sim = _check(db, strings, n)

		if (highest is None) or (sim["ratio"] > highest["ratio"]):
			highest = sim

	# db.close()
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
			print "%s v%s (%f)" % (result["libname"], result["version"], result["ratio"])
		else:
			print "No matching result"
	else:
		print "Invalid mode"
