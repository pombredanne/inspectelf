#!/usr/bin/python
import code

from pymongo import MongoClient
import pydb

if __name__ == "__main__":
	db = pydb.pydb(pydb.MongoConn(MongoClient("mongodb://localhost:27017/")))

	for library in db:
		for v in db[library]["versions"]:
			print "Mapping version to hashes for %s v%s" % (library, v)
			for h in db[library]["versions"][v]["hashes"]:
				if "version" not in db[library]["hashes"][h]:
					print h
					db[library]["hashes"][h]["version"] = v
