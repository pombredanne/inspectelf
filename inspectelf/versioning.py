#!/usr/bin/python

import pprint
import argparse
from string_cmp import read_strings
import re
import os
import string
import urllib2
import unix_ar
import tarfile
import tempfile
import gzip
import shutil
from HTMLParser import HTMLParser

# For xz
try:
	import lzma
except:
	from backports import lzma

def strings(filename, min=4):
	# with open(filename, errors="ignore") as f:  # Python 3.x
	with open(filename, "rb") as f:           # Python 2.x
		result = ""
		for c in f.read():
			if c in string.printable:
				result += c
				continue
			if len(result) >= min:
				yield result
			result = ""
		if len(result) >= min:  # catch result at EOF
			yield result

def version(elffile):
	strs = strings(elffile)

	for s in strs:
		#if "version" in s:
		#	print s
		patterns = []
		patterns.append("v([0-9]+\.[0-9]+\.[0-9]+)")
		patterns.append("([0-9]+\.[0-9]+\.[0-9]+)")
		# patterns.append("([0-9]+\.[0-9]+)")
		for p in patterns:
			m = re.match(".*%s.*" % p, s)

			if m is not None:
				print m.groups()[0]
				print s
				break
class Parser(HTMLParser):
	def __init__(self, baseurl):
		HTMLParser.__init__(self)
		self.versions = {}
		self.extensions = ["dsc", "deb", "xz", "gz", "tar", "debian"]
		self.baseurl = baseurl

	def handle_starttag(self, tag, attrs):
		if tag == "a":
			for attr in attrs:
				if attr[0] != "href":
					continue

				url = attr[1]
				m = re.match(".+(\d+\.\d+\.\d+[a-z]?).*", url)
				if m is not None:
					v = m.groups()[0]
					if v not in self.versions:
						self.versions[v] = []

					libname = url

					# Sanitize extensions
					for ext in self.extensions:
						if libname.endswith(ext):
							libname = libname[:-(len(ext) + 1)]

					self.versions[v].append({"libname": libname, "link": "%s%s%s" % (self.baseurl, os.path.sep, url)})
					# print m.groups()[0]
def download_versions(projname, versions):
	if not os.path.exists("dl"):
		os.mkdir("dl")

	projpath = "dl/%s" % (projname)
	if not os.path.exists(projpath):
		os.mkdir(projpath)

	for v in versions:
		vfound = False

		vpath = "%s/%s" % (projpath, v)
		if not os.path.exists(vpath):
			os.mkdir(vpath)

		for b in versions[v]:
			# Clean empty folders
			found = False

			if not b["link"].endswith("deb"):
				continue

			# Get download path
			libdl = "%s/%s/%s" % (projpath, v, b["libname"])

			# Check if directory exists
			if not os.path.exists(libdl):
				os.mkdir(libdl)

			base = os.path.basename(b["link"])
			basepath = "%s%s%s" % (libdl, os.path.sep, base)

			if not os.path.exists(basepath):
				os.mkdir(basepath)

			archive = "%s%s%s" % (basepath, os.path.sep, base)

			with open(archive, "w") as f:
				print "Downloading %s" % (b["link"])
				u = urllib2.urlopen(b["link"])
				f.write(u.read())

			# Extract files
			print "Extracting", archive
			arch = unix_ar.open(archive, "r")
			for n in arch.infolist():
				# print n.name
				if "data.tar.xz" == n.name:
					# Extract
					arch.extract(n.name, basepath)

					# Get file path
					datapath = "%s%s%s" % (basepath, os.path.sep, n.name)

					# Extract xz
					#with gzip.open(datapath, 'rb') as gz:
					#	data = gz.read()
					xz = lzma.open(datapath)

					# Read decompressed content
					# print dir(xz)
					data = xz.read()

					with tempfile.NamedTemporaryFile() as f:
						# Write and reset caret
						f.write(data)
						f.seek(0)

						# Create temporary file
						t = tarfile.open(f.name)
						for tarname in t.getnames():
							if tarname.endswith(".so"):
								t.extract(tarname, basepath)

								# Move the shared object to a shorter directory
								os.rename(os.path.sep.join([basepath, tarname]), os.path.sep.join([libdl, os.path.basename(tarname)]))

								# Don't clean this directory
								vfound = found = True

								print tarname

						t.close()

					xz.close()

					# Erase
					os.unlink(datapath)

			arch.close()
			os.unlink(archive)

			if not found:
				shutil.rmtree(libdl)
			else:
				shutil.rmtree(basepath)
		if not vfound:
			shutil.rmtree(vpath)

def versions(url):
	u = urllib2.urlopen(url) #"http://ports.ubuntu.com/ubuntu-ports/pool/main/o/openssl/")
	data = u.read()
	parser = Parser(url) #"http://ports.ubuntu.com/ubuntu-ports/pool/main/o/openssl/")
	parser.feed(data)

	# Clean trailing /
	if url[-1] == '/':
		url = url[:-1]

	print "Project name: %s" % url.split('/')[-1]
	download_versions(url.split('/')[-1], parser.versions)
	pp = pprint.PrettyPrinter(depth=6)
	# pp.pprint(parser.versions)

if __name__ == "__main__":
	# versions("http://ports.ubuntu.com/ubuntu-ports/pool/main/libs/libshout/")
	# versions("http://il.archive.ubuntu.com/ubuntu/pool/main/o/openssl/")
	# exit()
	parser = argparse.ArgumentParser()
	parser.add_argument("url", help = "Debian package list url")

	# Parse arguments
	args = parser.parse_args()

	versions(args.url)

