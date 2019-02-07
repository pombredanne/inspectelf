#!/usr/bin/python

from glob import glob
import os
import re
import argparse
import clang.cindex
from ignores import ignore_strings

# Fix clang binding path
clang.cindex.Config.set_library_file("/usr/lib/x86_64-linux-gnu/libclang-5.0.so.1")
#for x in dir(clang.cindex.CursorKind):
#	if "method" in x.lower() or "func" in x.lower():
#		print x

def _cmacros(node):
	macros = []

	if node.kind == clang.cindex.CursorKind.MACRO_DEFINITION:
		if not node.displayname.startswith("_") and \
			not node.displayname.endswith("_H") and \
			node.displayname == node.displayname.upper():
			print node.displayname
			macros.append(node.displayname)
			print node.displayname

	for c in node.get_children():
		macros += _cmacros(c)

	return macros

def src_strings(filename):
	pattern = re.compile("\"([^\"]+)\"")

	strs = []

	with open(filename, "r") as f:
		for line in f.read().split('\n'):
			m = pattern.findall(line)

			if len(m) > 0:
				strs += m

	return strs

def collect_macros(filename):
	files = [y for x in os.walk(os.path.dirname(filename)) for y in glob(os.path.join(x[0], '*'))]

	index = clang.cindex.Index.create()

	macros = set()

	args = ["-I%s" % (os.path.dirname(filename))]

	for f in files:
		if os.path.isdir(f):
			continue

		if not os.path.exists(f):
			continue

		if not f.endswith(".h"):
			continue

		print "Parsing %s" % f

		_tu = index.parse(f, args = args, options = clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
		macros = macros.union(set(_cmacros(_tu.cursor)))

	return macros

def _cstrings(node):
	strs = []
	#if node.kind in (clang.cindex.CursorKind.MACRO_INSTANTIATION, clang.cindex.CursorKind.MACRO_DEFINITION):
	#	print 'Found %s Type %s DATA %s' % (node.displayname, node.kind, node.data)

	if node.kind == clang.cindex.CursorKind.STRING_LITERAL:
		strs.append(node.spelling[1:-1])

	for c in node.get_children():
		strs += _cstrings(c)

	return strs

def _cfuncs(node):
	funcs = []

	if node.kind == clang.cindex.CursorKind.CXX_METHOD or \
		node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
			if node.spelling not in ignore_strings:
				# print "Appendeing %s" % node.spelling
				funcs.append(node.spelling)

	for c in node.get_children():
		funcs += _cfuncs(c)

	return funcs

def clang_parse(filename, debug = False):
	# print "\rCLANG %s..." % filename + " " * 32,
	index = clang.cindex.Index.create()

	args = ["-I%s" % (os.path.dirname(filename))]

	# macros = collect_macros(filename)

	# args += ["-D%s" % m for m in macros]

	# print args

	tu = index.parse(filename, args = args, options = clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)

	strs = src_strings(filename)

	return {"strings": list(set(strs).union(set(_cstrings(tu.cursor)))), "functions": _cfuncs(tu.cursor)}

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Build C/C++ source files with CLang to extract hardcoded strings and function names")
	parser.add_argument("file", help = "C/C++ File")

	args = parser.parse_args()

	print clang_parse(args.file)
