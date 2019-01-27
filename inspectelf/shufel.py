#!/usr/bin/python

import os
import pickle

class Shufel(dict):
	def __init__(self, filename):
		self.filename = filename

		# Initialize dict
		dict.__init__(self)

		# Load existing file
		if os.path.exists(self.filename):
			with open(self.filename, "rb") as f:
				d = pickle.load(f)

				# Copy data
				for k in d.keys():
					self[k] = d[k]

	def sync(self):
		with open(self.filename, "wb") as f:
			pickle.dump(self, f)

	def __setitem__(self, key, value):
		dict.__setitem__(self, key, value)

		self.sync()
