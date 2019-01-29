#!/usr/bin/python

import argparse
import clang.cindex
from ignores import ignore_strings

# Fix clang binding path
clang.cindex.Config.set_library_file("/usr/lib/x86_64-linux-gnu/libclang-5.0.so.1")
#for x in dir(clang.cindex.CursorKind):
#	if "method" in x.lower() or "func" in x.lower():
#		print x

def _cstrings(node):
	strs = []
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
				funcs.append(node.spelling)

	for c in node.get_children():
		funcs += _cfuncs(c)

	return funcs

def clang_parse(filename):
	# print "\rCLANG %s..." % filename + " " * 32,
	index = clang.cindex.Index.create()
	tu = index.parse(filename)

	return {"strings": _cstrings(tu.cursor), "functions": _cfuncs(tu.cursor)}

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Build C/C++ source files with CLang to extract hardcoded strings and function names")
	parser.add_argument("file", help = "C/C++ File")

	args = parser.parse_args()

	print clang_strings(args.file)
