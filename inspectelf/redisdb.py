#!/usr/bin/python

import redis
import uuid
import pickle
import code
from redis_collections import Dict, List, Set

def _retype(obj):
	if type(obj) == dict:
		return redict
	elif type(obj) == list:
		return relist
	else:
		return redata

class _rebase:
	def __init__(self, conn, id = None):
		self._conn = conn

		self._id = id
		self._create()

	def _create(self):
		if self._id is not None:
			self._conn.set(self._id, pickle.dumps(None), nx = True)
		else:
			id = str(uuid.uuid4())

			while self._conn.set(id, pickle.dumps(None), nx = True) is None:
				id = str(uuid.uuid4())

			self._id = id

	def _set(self, data):
		self._conn.set(self._id, pickle.dumps(data))

	def _get_data(self):
		return pickle.loads(self._conn.get(self._id))

	def _get(self, id):
		# Get the data
		data = pickle.loads(self._conn.get(id))

		# Decide on object type
		reobj = _retype(data)(self._conn)

		reobj._id = id

		return reobj

	def d(self):
		return self._get_data()

class redata(_rebase):
	# Data is a regular type (int or string)
	def __init__(self, conn, id = None):
		_rebase.__init__(self, conn, id)

	def _initialize(self, data):
		# Set the data on creation
		self._set(data)

class relist(_rebase):
	def __init__(self, conn, id = None):
		_rebase.__init__(self, conn, id)

	def append(self, data):
		keys = self._get_data()

		reobj = _retype(data)(self._conn)
		reobj._initialize(data)
		keys.append(reobj._id)

		self._set(keys)

	def __len__(self):
		return len(self._get_data())

	def _initialize(self, data):
		keys = []
		for d in data:
			reobj = _retype(d)(self._conn)
			reobj._initialize(d)
			keys.append(reobj._id)

		self._set(keys)

	def __getitem__(self, index):
		keys = self._get_data()

		if index >= len(keys):
			raise Exception("Index %d is out of bounds" % index)

		return self._get(keys[index])

class redict(_rebase):
	def __init__(self, conn, id = None):
		_rebase.__init__(self, conn, id)

	def keys(self):
		return self.d().keys()

	def __len__(self):
		return len(self.keys())

	def __iter__(self):
		self._iter_idx = 0

		return self

	def next(self):
		if self._iter_idx == len(self):
			raise StopIteration

		x = self.keys()[self._iter_idx]
		self._iter_idx += 1
		return x

	def _initialize(self, data):
		keys = {}

		# Set data
		for k in data.keys():
			reobj = _retype(data[k])(self._conn)
			reobj._initialize(data[k])
			keys[k] = reobj._id

		self._set(keys)

	def __getitem__(self, key):
		keys = self._get_data()

		if key not in keys:
			print keys
			raise Exception("No existing key [%s] in dict" % key)

		d = self._get(keys[key])

		if isinstance(d, redata):
			return d.d()
		return d

	def __setitem__(self, key, value):
		keys = self._get_data()

		reobj = _retype(value)(self._conn)
		reobj._initialize(value)

		keys[key] = reobj._id

		# Rewrite
		self._set(keys)

class redisdb(redict):
	def __init__(self, conn):
		redict.__init__(self, conn, "root")

		# Initialize root if neccessary
		if self._get_data() is None:
			self._set({})

if __name__ == "__main__":
	conn = redis.Redis(host = "localhost", port = 6379)

	db = redisdb(conn)

	code.interact(local = {"db": db})
