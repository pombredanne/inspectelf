#!/usr/bin/python

import argparse

# Compression Algorithms
import gzip
import bz2
import backports.lzma

import tempfile
from os.path import basename
import magic

# Gzip has an issue with reading trailing garbage. Read byte-by-byte.
# NOTE: This CAN be optimized.
def gzip_read(g):
	b = ""
	buddies = [ 2 ** i for i in xrange(12) ][::-1]
	
	for buddy in buddies:
		while True:
			try:
				b += g.read(buddy)
			except:
				break

	return b

def vmlinuz(filename):
	filters = {
			'\037\213\010': "gzip",
				
			'\3757zXZ\000': "xz",
				
			'BZh': "bzip2",
				
			'\135\0\0\0': "lzma",
				
			'\211\114\132': "lzop",
				
			'\002!L\030': "lz4",
				
			'(\265/\375': "zstd"
		}

	with open(filename) as f:
		d = f.read()
		
		for f in filters:
			pos = d.find(f)
			if pos != -1:
				# print filters[f]
				with tempfile.TemporaryFile() as tmp:
					tmp.write(d[pos:])
					tmp.flush()
					tmp.seek(0)
					
					if filters[f] == "gzip":
						gz = gzip.GzipFile(fileobj = tmp, mode = 'rb')
						
						# Read the kernel image
						kernel = gzip_read(gz)

						if kernel is None:
							raise Exception("Error reading gzip compression")

					elif filters[f] == "bzip2":
						kernel = bz2.decompress(d[pos:])
					elif filters[f] == "lzma":
						kernel = backports.lzma.decompress(d[pos:])

					# print magic.detect_from_content(kernel)
					
					if magic.detect_from_content(kernel).mime_type == "application/x-executable":
						return kernel

		raise Exception("Unsupported vmlinuz compression")
	
def kconfig(filename):
	m = magic.detect_from_filename(filename)

	# print m
	if basename(filename).startswith("vmlinuz"):
		# print magic.detect_from_filename(filename)

		with tempfile.NamedTemporaryFile() as tmp:
			kernel = vmlinuz(filename)
			
			with open("kernel", "wb") as f:
				f.write(kernel)
			
			tmp.write(kernel)
			tmp.flush()
			tmp.seek(0)
			
			return kconfig(tmp.name)
			

	with open(filename, "rb") as f:
		d = f.read()

		off = d.find("IKCFG_ST\037\213\010") + 8
				
		f.seek(off)

		g = gzip.GzipFile(fileobj = f, mode = 'rb')

		data = gzip_read(g)

	if len(data) == 0:
		raise Exception("No .config file")

	return data

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Extract Linux kernel configuration file")
	parser.add_argument("kernel", help = "Linux Kernel File (vmlinux)")

	args = parser.parse_args()

	print kconfig(args.kernel)
