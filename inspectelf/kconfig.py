#!/usr/bin/python

import argparse
import gzip
import tempfile

# Gzip has an issue with reading trailing garbage. Read byte-by-byte.
# NOTE: This CAN be optimized.
def gzip_read(g):
	b = ""
	while True:
		try:
			b += g.read(1)
		except:
			break
	return b

def kconfig(filename):
	with open(filename, "rb") as f:
		d = f.read()

		off = d.find("IKCFG_ST\037\213\010") + 8

		f.seek(off)

		g = gzip.GzipFile(fileobj = f, mode = 'rb')

		data = gzip_read(g)
	return data

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Extract Linux kernel configuration file")
	parser.add_argument("kernel", help = "Linux Kernel File (vmlinux)")

	args = parser.parse_args()

	print kconfig(args.kernel)
