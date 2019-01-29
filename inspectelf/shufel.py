#!/usr/bin/python

import os
import pickle

def _recurse_save(obj):
	d = {}
	for k in obj:
		if isinstance(obj[k], Shufel):
			d[k] = {}
			d[k]["_shufel"] = True
			d[k]["_collections"] = obj[k].collections
			res = _recurse_save(obj[k].d)

			for key in res:
				d[k][key] = res[key]
		else:
			d[k] = obj[k]

	return d

def _recurse_load(d):
	obj = {}

	# Types other than dicts, parse normally
	if type(d) != dict:
		return d

	for k in d:
		if "_shufel" in d[k] and d[k]["_shufel"]:
			obj[k] = Shufel()
			obj[k].collections = d[k]["_collections"]

			regulars = d[k].keys()
			regulars.remove("_shufel")
			regulars.remove("_collections")

			for collection in obj[k].collections:
				obj[k].d[collection] = d[k][collection]
				obj[k].d["_common_" + collection] = d[k]["_common_" + collection]

				regulars.remove(collection)
				regulars.remove("_common_" + collection)

			for key in regulars:
				obj[k].d[key] = _recurse_load(d[k][key])

		else:
			obj[k] = _recurse_load(d[k])

	return obj

class Shufel:
	def __init__(self, filename = None):
		# Initialize dict
		self.d = {}
		self.collections = []
		self.filename = filename

		# Load existing file
		if filename is not None and os.path.exists(filename):
			with open(self.filename, "rb") as f:
				d = pickle.load(f)

				# Parse data from file
				self.d = _recurse_load(d)

	def sync(self):
		if self.filename is not None:
			with open(self.filename, "wb") as f:
				pickle.dump(_recurse_save(self.d), f)

	def cdef(self, collection):
		self.d[collection] = {}
		self.d["_common_" + collection] = set()
		self.collections.append(collection)

	def cget(self, collection, key):
		if collection in self.collections:
			return self.d[collection][key].union(self.d["_common_" + collection])
		return self[collection][key]

	def cinsert(self, collection, key, value):
		if type(value) != list and type(value) != set:
			self.d[collection][key] = value

			return

		# Convert value into a set
		if type(value) != set:
			value = set(value)

		if collection not in self.d:
			# Create a new collection
			self.cdef(collection)

		# Initialize common with first value
		if len(self.d["_common_" + collection]) == 0:
			self.d["_common_" + collection] = value

		# Calculate the new common
		common = self.d["_common_" + collection].intersection(value)

		# If the new common is smaller than the current common, update common
		if len(self.d["_common_" + collection]) < len(common):
			common = self.d["_common_" + collection]
		else:
			# Find the diff to add to everyone else
			diff = self.d["_common_" + collection] - common

			# Update all other keys
			for k in self.d[collection]:
				self.d[collection][k] = self.d[collection][k].union(diff)

			# Update common
			self.d["_common_" + collection] = common

		self.d[collection][key] = value - common

	def keys(self):
		return self.d.keys()

	def __setitem__(self, key, value):
		self.d[key] = value

		self.sync()

	def __getitem__(self, key):
		if key not in self.d:
			raise Exception("No such key %s" % str(key))

		obj = self.d[key]

		return obj
