#!/usr/bin/python

import traceback
import json
import pprint
import argparse
import re
import os
import magic
import string
import urllib
import urllib2
import tarfile
import tempfile
import gzip
import shutil
import arpy
from tempfile import *
from rpm2cpio import *
from libarchive import *
from HTMLParser import HTMLParser
from shufel import Shufel
# from shove import Shove
# Shufel = Shove

# For xz
try:
	import lzma
except:
	from backports import lzma

src_pkgs = ["xz", "gz"]
# src_pkgs = []
extensions = ["rpm", "deb"] + src_pkgs

class Parser(HTMLParser):
	def __init__(self, baseurl):
		HTMLParser.__init__(self)
		self.links = []
		self.subdirs = []
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

				should_download = False
				for ext in extensions:
					if url.endswith(".%s" % ext):
						should_download = True
						break

				if not should_download:
					continue

				p = re.compile('(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*')

				if url[0] == '/':
					m = p.search(self.baseurl)

					full_url = os.path.sep.join(("http:/", m.group("host"), url))
				else:
					full_url = os.path.sep.join((self.baseurl, url))

				self.links.append(full_url)

def library_name(filename):
	# Get the library name
	if filename.startswith("python-"):
		m = re.match("python-([a-zA-Z]+)[-_].*", filename)
	else:
		m = re.match("([a-zA-Z]+)[-_\.].*", filename)

		if m is None:
			m = re.match("([a-zA-Z]+)[0-9].*", filename)


	if m is None:
		return None

	# Get the library name
	return m.groups()[0]

def dissect_links(links):
	global dldb

	libraries = {}

	if "cache" not in dldb.keys():
		print "Reset DB"
		dldb["cache"] = []

	for link in links:
		# Don't download anything that's already been downloaded.
		if link in dldb["cache"]:
			print "Already parsed: %s" % link
			continue

		# Get the filename to be downloaded
		filename = link[link.rfind('/') + 1:]

		# Get the library name
		libname = library_name(filename)

		if libname is None:
			continue

		if libname not in libraries:
			libraries[libname] = {}

		v = "0"

		if libname == "openssl" or libname == "libssl" or libname == "libcrypto":
			# print filename
			m = re.match(".+(\d\.\d\.\d[a-z]).*" , filename)

			if m is None:
				m = re.match(".+(\d\.\d\.\d).*" , filename)

			v = m.groups()[0]
		else:
			# Pattern \d+\.\d+\.\d+ might fish dates from time to time X_X
			patterns = [".+[\-_](\d+\.\d+\.\d+[a-z]?).*", ".+[\-_](\d+\.\d+\.\d+).*", ".+[\-_](\d+\.\d+).*"]
			for p in patterns:
				m = re.match(p, filename)
				if m is not None:
					v = m.groups()[0]
					break

		if v not in libraries[libname]:
			libraries[libname][v] = []

		libraries[libname][v].append({"libname": filename, "link": link})

	return libraries

def extract_deb(archive, basepath, libdl):
	found = False
	arch = arpy.Archive(archive)
	arch.read_all_headers()

	for n in arch.archived_files.keys():
		# print n.name
		if "data.tar.xz" == n:
			# Extract
			with open(os.path.sep.join((basepath, n)), "wb") as f:
				f.write(arch.archived_files[n].read())

			# Get file path
			datapath = os.path.sep.join((basepath, n))

			# Extract xz
			xz = lzma.open(datapath)

			# Read decompressed content
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

						try:
							if "application/x-sharedlib" not in magic.detect_from_filename(localpath).mime_type:
								os.unlink(localpath)
								continue
						except:
							os.unlink(localpath)
							continue

						# Move the shared object to a shorter directory
						os.rename(os.path.sep.join([basepath, tarname]), os.path.sep.join([libdl, os.path.basename(tarname)]))

						# Don't clean this directory
						found = True

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

	return found

def extract_rpm(archive, basepath, libdl):
	found = False
	with open(archive, "rb") as f:
		with TemporaryFile() as t:
			# Convert to CPIO
			rpm2cpio(f, t)

			# Rewind to start
			t.seek(0)

			# Parse file
			a = Archive(t)

			for p in a.iterpaths():
				if p.endswith(".so") or p.endswith(".a") or ".so." in p:
					dirs = os.path.dirname(p)

					# Check if path exists before creating it
					if not os.path.exists("./%s" % dirs):
						os.makedirs("./%s" % dirs)

					# Extract
					a.readpath(p)

					# Remove side effects
					if os.path.exists("./%s" % os.path.basename(p)):
						shutil.rmtree("./%s" % os.path.basename(p))

					if "application/x-sharedlib" not in magic.detect_from_filename("./%s" % p).mime_type:
						os.unlink(p)
						shutil.rmtree("./usr/")
						continue

					print "Found: %s" % p

					print "Moving to %s" % os.path.sep.join([libdl, os.path.basename(p)])

					os.rename("./%s" % p, os.path.sep.join([libdl, os.path.basename(p)]))

					shutil.rmtree("./usr/")

					found = True

	# Erase all working directories
	if not found:
		print "Removing %s" % libdl
		shutil.rmtree(libdl)
	else:
		print "Removing %s" % basepath
		shutil.rmtree(basepath)

	return found

def extract_src_tar(tardata, basepath, libdl):
	src_ext = ["c", "cpp", "h", "hpp", "cc"]
	found = False

	with tempfile.NamedTemporaryFile() as f:
		# Write and reset caret
		f.write(tardata)
		f.seek(0)

		# Create temporary file
		t = tarfile.open(f.name)
		for tarname in t.getnames():
			#print tarname
			# Extract ALL SOURCE FILES:
			extfound = False
			for ext in src_ext:
				if tarname.endswith(".%s" % ext):
					extfound = True
					break

			if not extfound:
				continue

			print os.path.sep.join((basepath, tarname))
			t.extract(tarname, basepath)
			basedir = tarname.split('/')[0]
			found = True

	if found:
		print "Found. Renaming %s -> %s ..." % (os.path.sep.join((basepath, basedir)), os.path.sep.join((libdl, basedir)))
		shutil.move(os.path.sep.join((basepath, basedir)), os.path.sep.join((libdl, basedir)))

	return found

def extract_src(archive, basepath, libdl):
	print "Source package"
	found = False

	if archive.endswith(".xz"):
		# Extract xz
		xz = lzma.open(archive)

		# Read decompressed content
		found = extract_src_tar(xz.read(), basepath, libdl)

	elif archive.endswith(".gz"):
		with gzip.open(archive, "rb") as f:
			try:
				found = extract_src_tar(f.read(), basepath, libdl)
			except:
				found = False

	# Erase all working directories
	if not found:
		print "Removing %s" % libdl
		shutil.rmtree(libdl)
	else:
		print "Removing %s" % basepath
		shutil.rmtree(basepath)

	return found

def extract(archive, basepath, libdl):
	print "Extracting", archive

	if archive.endswith(".deb"):
		return extract_deb(archive, basepath, libdl)
	elif archive.endswith(".rpm"):
		return extract_rpm(archive, basepath, libdl)
	else:
		for ext in src_pkgs:
			if archive.endswith(".%s" % ext):
				return extract_src(archive, basepath, libdl)

		raise Exception("Unsupported file type")

def download_versions(projname, versions):
	if not os.path.exists("dl"):
		os.mkdir("dl")

	dfound = False

	projpath = os.path.sep.join(("dl", projname))
	if not os.path.exists(projpath):
		os.mkdir(projpath)

	for v in versions:
		vfound = False

		vpath = os.path.sep.join((projpath, v))
		if not os.path.exists(vpath):
			os.mkdir(vpath)

		afound = False

		for b in versions[v]:
			# Setup architecture folder
			arch = ["amd64", "i386", "armel", "armhf", "aarch64", "arm64", "powerpc", "ppc64el", "s390x"]
			found_arch = False
			archpath = os.path.sep.join((projpath, v, "src"))

			for a in arch:
				if b["link"][:b["link"].rfind(".")].endswith(a):
					archpath = os.path.sep.join((projpath, v, a))
					found_arch = True
					break

			# Check if it's a source package
			for ext in src_pkgs:
				if b["link"].endswith(ext):
					found_arch = True
					break

			if not found_arch:
				continue

			if not os.path.exists(archpath):
				os.mkdir(archpath)

			# Get download path as the pkg arch
			libdl = os.path.sep.join((archpath, b["libname"]))

			# Check if directory exists
			if not os.path.exists(libdl):
				os.mkdir(libdl)

			base = os.path.basename(b["link"])
			basepath = os.path.sep.join((libdl, base))

			if not os.path.exists(basepath):
				os.mkdir(basepath)

			archive = os.path.sep.join((basepath, base))

			with open(archive, "w") as f:
				print "Downloading %s" % (b["link"])
				u = urllib2.urlopen(b["link"])
				f.write(u.read())

			# Extract files
			if extract(archive, basepath, libdl):
				afound = dfound = vfound = True

			# Mark that this download was already processed
			dldb["cache"].append(b["link"])

			dldb.sync()

			if not afound:
				shutil.rmtree(archpath)

		if not vfound:
			shutil.rmtree(vpath)
	if not dfound:
		shutil.rmtree(projpath)

def versions(url):
	print url
	u = urllib2.urlopen(url)
	data = u.read()
	parser = Parser(url)
	parser.feed(data)

	for subdir in parser.subdirs:
		versions(subdir)

	print "Found %d suitable packages" % len(parser.links)

	libraries = dissect_links(parser.links)

	# Download everything per library
	for libname in libraries:
		download_versions(libname, libraries[libname])

if __name__ == "__main__":
	dldb = Shufel("dldb")

	parser = argparse.ArgumentParser(description = "Download Debian, RPM, Source packages and create a basic library-to-version sparse database")
	parser.add_argument("url", help = "Debian package list url")

	# Parse arguments
	try:
		args = parser.parse_args()

		versions(args.url)
	except Exception as e:
		print "EXCEPTION"
		print e
