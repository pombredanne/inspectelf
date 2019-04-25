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
from cfuncs import ctags
from cstrings import clang_parse
import time
from console_progressbar import ProgressBar

from pymongo import MongoClient
import pydb

def versplit(v):
	res = []
	s = ""
	for c in v:
		if (len(s) == 0 or s[-1].isalpha() == c.isalpha()) and c != '.':
			s += c
		else:
			res.append(s)
			if c != '.':
				s = c
			else:
				s = ""
	if len(s) > 0:
		res.append(s)

	return res

def vercmp(v0, v1):
	v0 = versplit(v0)
	v1 = versplit(v1)

	# Pad to normalize lengths
	if len(v0) < len(v1):
		v0 += ["0"] * (len(v1) - len(v0))
	else:
		v1 += ["0"] * (len(v0) - len(v1))

	for x, y in zip(v0, v1):
		if len(x) == len(y) == 1:
			x = ord(x)
			y = ord(y)
		else:
			x = int(x)
			y = int(y)

		if x > y:
			return 1
		elif x < y:
			return -1
	return 0

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
		# print "Source %s v%s already parsed" % (proj, version)
		return

	print "Processing %s v%s..." % (proj, version)

	# List all files in directory
	files = [y for x in os.walk(srcpath) for y in glob(os.path.join(x[0], '*'))]

	strs = set()
	funcs = set()
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

		if hash in _db[proj]["srcs"]: # and hash != "9f9f4c5d29b390035c00a4f5774d41c374b40d5bd9bf6c8f9c83c06007c48b2c":
			pass
			#print "%s already indexed" % hash
		else:
			# print "Building %s" % f
			try:
				res = clang_parse(f) # , debug = hash == "9f9f4c5d29b390035c00a4f5774d41c374b40d5bd9bf6c8f9c83c06007c48b2c")
				ctags_funcs = ctags(f)

				# print res

				fun = set(res["functions"]).union(ctags_funcs)
				s = set(res["strings"])
			except Exception, e:
				print "Error in building source file %s" % f, e
				continue

			_db[proj]["srcs"][hash] = {}
			_db[proj]["srcs"][hash]["functions"] = fun
			_db[proj]["srcs"][hash]["strings"] = s

		funcs = funcs.union(_db[proj]["srcs"][hash]["functions"])
		strs = strs.union(_db[proj]["srcs"][hash]["strings"])

	print "Strings: %d Functions: %d" % (len(strs), len(funcs))

	# Add to db
	learn(_db, proj, strs, version, funcs)

def build_db(root):
	#db = redisdb(redis.Redis(host = "localhost", port = 6379))
	db = pydb.pydb(pydb.MongoConn(MongoClient("mongodb://localhost:27017/")), cache = True)

	# First directory heirarchy holds project names
	for proj in os.listdir(root):
		# Create a new project in db
		if proj not in db.keys():
			db[proj] = {}
			db[proj]["hashes"] = {}
			db[proj]["srcs"] = {}
			db[proj]["versions"] = {}
			db[proj]["base_version"] = None

		for version in os.listdir(os.path.sep.join((root, proj))):
			for arch in os.listdir(os.path.sep.join((root, proj, version))):
				for candidate in os.listdir(os.path.sep.join((root, proj, version, arch))):
					c = os.path.sep.join((root, proj, version, arch, candidate))

					if arch == "src":
						_process_src(db, proj, version, c)
					else:
						_process_library(db, proj, version, arch, c)

def _version_functions(_db, proj, version):
	funcs = set()

	for h in _db[proj]["versions"][version]["hashes"]:
		try:
			funcs = funcs.union(_db[proj]["hashes"][h]["functions"])
		except:
			continue

	return funcs

def _hash_to_version(library, h):
	# Try fast path
	if "version" in library["hashes"][h]:
		return library["hashes"][h]["version"]

	# If for some weird reason there isn't one, try the slow one
	for v in library["versions"]:
		print "Checking for version %s" % v
		for hv in library["versions"][v]["hashes"]:
			if hv == h:
				print "%s = %s" % (h, v)
				library["hashes"]["version"] = v
				return v

	return None

def _string_similarity(library, target_set):
	highest_ratio = 0
	highest_instance = None

	# print target_set

	for h in library["hashes"].keys():
		# version_set = library["hashes"][h]["strings"]
		version_set = set(library["hashes"][h]["strings"]).union(set(library["hashes"][h]["functions"]))

		#if library["hashes"][h]["functions"] is not None:
		#	version_set = version_set.union(library["hashes"][h]["functions"])

		# TODO: Decide which one of these two calculations is better.
		# The first one yields much lower percentages as the strings gathered from sources
		# will always be larger in numbers than those gathered from the binary itself.
		# Comparing according to lower numbers may yield inaccurate false positives with
		# close versions...
		ratio = len(set.intersection(version_set, target_set)) / float(len(set.union(version_set, target_set)))

		# if ratio > 0.09 or ratio < 0.025:
		# 	print set.intersection(version_set, target_set)

		ratio = len(set.intersection(version_set, target_set)) / float(len(target_set))
		print "%s = %f" % (_hash_to_version(library, h), ratio)

		if ratio > highest_ratio:
			highest_ratio = ratio
			highest_instance = h

	highest_version = _hash_to_version(library, highest_instance)

	return {"version": highest_version, "ratio": highest_ratio}

def _function_similarity(library, target_set):
	ret_ver = prev_ver = ver = library["base_version"]

	while ver is not None:
		ver_funcs = library["versions"][ver]["funcs_diff"]

		# Check if within the string pool there's some with the version-specific functions.
		# If not, return the previous version
		if len(ver_funcs.intersection(target_set)) == 0:
			ret_ver = prev_ver

		# Remember the previous version to return as valid version
		prev_ver = ver

		# Advance to next version
		ver = library["versions"][ver]["next"]

	return ret_ver

def identify(_db, proj, strs):
	# String similarity
	str_similarity = _string_similarity(_db[proj], set(strs))
	func_similarity = _function_similarity(_db[proj], set(strs))

	print "Function differential analysis version detected: %s" % (func_similarity)

	visit_map = []
	latest_version = None

	# Find all the hashes that have
	"""
	for v in _db[proj]["versions"]:
		for h in _db[proj]["versions"][v]:
			symbols = _db[proj]["hashes"][h]["next"]["diff"]

			visit_map.append(h)

			if len(set(strs).intersection(symbols)) > 0:
				latest_version = _hash_to_version(proj, h)
	"""
	return {"libname": proj, "version": str_similarity["version"], "ratio": str_similarity["ratio"]}


def similarity(filename):
	db = pydb.pydb(pydb.MongoConn(MongoClient("mongodb://localhost:27017/")), cache = True)

	libname = library_name(os.path.basename(filename))

	if libname is None:
		raise Exception("Unsupported library name")

	strs = set([ s for s in strings(filename) ])

	# Library not indexed!
	if libname in db and len(db[libname].keys()) > 0:
		print "Checking %s" % libname
		return identify(db, libname, strs)

	highest_ratio = 0
	highest_result = 0

	# Try to find what's the actual library is
	for libname in db:
		print "Checking %s" % libname
		result = identify(db, libname, strs)

		# print result

		if result["ratio"] > highest_ratio:
			highest_ratio = result["ratio"]
			highest_result = result

	return highest_result

def learn(_db, proj, strings, version, funcs):

	s = hashlib.sha256()
	s.update("".join(strings))

	if funcs is not None:
		s.update("".join(funcs))

		funcs = set(funcs)

	h = s.digest().encode("HEX")

	print "Hashing %d strings" % len(strings)
	print "Hash: %s" % h

	s = set(strings)

	_db[proj]["hashes"][h] = {}
	_db[proj]["hashes"][h]["strings"] = s

	if "versions_order" not in _db[proj]:
		_db[proj]["versions_order"] = []

	vlevel = _db[proj]["versions_order"]

	if version not in _db[proj]["versions"].keys():
		_db[proj]["versions"][version] = {
							"hashes": [],
							"next": None
						}

		if _db[proj]["base_version"] is None:
			_db[proj]["base_version"] = version
		else:
			# If we're parsing the lowest version, replace base pointer
			if vercmp(version, _db[proj]["base_version"]) < 0:
				_db[proj]["versions"][version]["next"] = _db[proj]["base_version"]
				_db[proj]["base_version"] = version

				_db[proj]["versions"][version]["funcs_diff"] = funcs
			else:
				prev_ver = _db[proj]["base_version"]

				# Find the previous version to link the new version to
				while _db[proj]["versions"][prev_ver]["next"] is not None and vercmp(version, _db[proj]["versions"][prev_ver]["next"]) > 0:
					prev_ver = _db[proj]["versions"][prev_ver]["next"]

				# Link the version in the chain
				_db[proj]["versions"][version]["next"] = _db[proj]["versions"][prev_ver]["next"]
				_db[proj]["versions"][prev_ver]["next"] = version

				# Calculate the functions differentiation between previous version and current one
				_db[proj]["versions"][version]["funcs_diff"] = funcs - _version_functions(_db, proj, prev_ver)

			# Calculate the diff against the next version
			nextver = _db[proj]["versions"][version]["next"]

			if nextver is not None:
				_db[proj]["versions"][nextver]["funcs_diff"] =  _version_functions(_db, proj, nextver) - funcs

	_db[proj]["versions"][version]["hashes"].append(h)

	# Try to figure out which functions are new in this version
	_db[proj]["hashes"][h]["functions"] = funcs

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
