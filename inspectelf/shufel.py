#!/usr/bin/python

import os
import pickle

class Shufel:
	def __init__(self, filename):
		self.filename = filename

		# Initialize dict
		self.d = {}

		# Load existing file
		if os.path.exists(self.filename):
			with open(self.filename, "rb") as f:
				d = pickle.load(f)

				# Copy data
				for k in d.keys():
					self.d[k] = d[k]

	def sync(self):
		with open(self.filename, "wb") as f:
			pickle.dump(self.d, f)

	def keys(self):
		return self.d.keys()

	def __setitem__(self, key, value):
		self.d[key] = value

		self.sync()

	def __getitem__(self, key):
		if key not in self.d:
			raise Exception("No such key %s" % str(key))

		return self.d[key]
