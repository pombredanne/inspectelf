#!/usr/bin/python
import code
import redis
from redisdb import *

if __name__ == "__main__":
	conn = redis.Redis(host = "localhost", port = 6379)

	db = redisdb(conn)

	code.interact(local = {"db": db})
