#!/usr/bin/python
import code

from pymongo import MongoClient
import pydb

if __name__ == "__main__":
	db = pydb.pydb(pydb.MongoConn(MongoClient("mongodb://localhost:27017/")))

	code.interact(local = {"db": db})
