#!/usr/bin/python

from subprocess import Popen, PIPE
import argparse

def ctags(filename):
	functions = []

	p = Popen(("ctags -f - %s" % filename).split(' '), stdout = PIPE)

	# Read stdout
	output = p.communicate()[0]

	for l in output.split('\n'):
		details = l.split('\t')

		# Add functions
		if details[-1] == 'f':
			functions.append(details[0])

	return functions

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Extract C functions from source files")

	parser.add_argument("file", help = "C File")

	args = parser.parse_args()

	print ctags(args.file)

