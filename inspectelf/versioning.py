#!/usr/bin/python

import pprint
import argparse
from string_cmp import read_strings
import re
import os
import magic
import string
import urllib
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

class Parser(HTMLParser):
	def __init__(self, baseurl):
		HTMLParser.__init__(self)
		self.links = []
		self.subdirs = []
		self.extensions = ["dsc", "deb", "xz", "gz", "tar", "debian"]
		self.baseurl = baseurl

	def handle_starttag(self, tag, attrs):
		if tag == "a":
			for attr in attrs:
				if attr[0] != "href":
					continue

				url = attr[1]

				# Mark subdirectories
				if url[0] != '/' and url[-1] == '/' and url.startswith("lib"):
					self.subdirs.append(os.path.sep.join((self.baseurl, url)))

				if not url.endswith(".deb"):
					continue

				p = re.compile('(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*')

				if url[0] == '/':
					m = p.search(self.baseurl)

					full_url = os.path.sep.join(("http:/", m.group("host"), url))
				else:
					full_url = os.path.sep.join((self.baseurl, url))

				self.links.append(full_url)

def dissect_links(links):
	libraries = {}

	for link in links:
		# Get the filename to be downloaded
		filename = link[link.rfind('/') + 1:]

		if filename.startswith("python-"):
			# Get the library name
			m = re.match("([a-zA-Z0-9]+)[-_].*", filename)
		else:
			m = re.match("python-([a-zA-Z0-9]+)[-_].*", filename)


		if m is None:
			continue

		# Get the library name
		libname = m.groups()[0]

		if libname not in libraries:
			libraries[libname] = {}

		patterns = [".+[\-_](\d+\.\d+\.\d+[a-z]?).*", ".+[\-_](\d+\.\d+).*"]
		for p in patterns:
			m = re.match(p, filename)
			if m is not None:
				v = m.groups()[0]
				if v not in libraries[libname]:
					libraries[libname][v] = []

				libraries[libname][v].append({"libname": filename, "link": link})

	return libraries

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

			if not b["link"].endswith(".deb"):
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
							if tarname.endswith(".so") or tarname.endswith(".a") or ".so." in tarname:
								t.extract(tarname, basepath)

								localpath = os.path.sep.join([basepath, tarname])

								if "application/x-sharedlib" not in magnum.id_filename(localpath):
									# print tarname, magnum.id_filename(localpath)
									os.unlink(localpath)
									continue

								# Move the shared object to a shorter directory
								os.rename(os.path.sep.join([basepath, tarname]), os.path.sep.join([libdl, os.path.basename(tarname)]))

								# Don't clean this directory
								vfound = found = True

								print "Found:", tarname

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
	print url
	u = urllib2.urlopen(url)
	data = u.read()
	parser = Parser(url)
	parser.feed(data)
	for subdir in parser.subdirs:
		versions(subdir)

	libraries = dissect_links(parser.links)

	# Download everything per library
	for libname in libraries:
		download_versions(libname, libraries[libname])

if __name__ == "__main__":
	magnum = magic.Magic(flags = magic.MAGIC_MIME)

	parser = argparse.ArgumentParser()
	parser.add_argument("url", help = "Debian package list url")

	# Parse arguments
	args = parser.parse_args()

	versions(args.url)

	magnum.close()
