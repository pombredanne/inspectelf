#!/usr/bin/python

import argparse
import pprint
# Compression Algorithms
import gzip
import bz2
import backports.lzma

import re
import tempfile
from os.path import basename
import magic

supported_archs = [ 'X86_64', 'X86_32', 'ARM64', 'ARM' ]

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

def detect_arch(config):
	arch = None

	for a in supported_archs:
		if a in config and config[a] == 'y':
			if arch is None:
				arch = a
			else:
				raise Exception("More than one supported architecture detected")
	if not arch:
		raise Exception("Failed detection architecture")
	else:
		return arch

def parse_kconfig(kconfig):
	config = {}
	non_matching = re.compile("# CONFIG_([A-Z0-9]+) is not set")
	for line in kconfig.split('\n'):
		c = line.split('=')
		if len(c) == 2:
			config[c[0][len("CONFIG_"):]] = c[1]
		else:
			m = non_matching.search(line)
			if m is not None:
				config[m.groups()[0]] = 'n'
				
	return config

def filter_kconfig(kconfig):
	arch = detect_arch(kconfig)
	FUZZY_BLACK_RULES = [
			]
	EXACT_BLACK_RULES = [
						"IKCONFIG",
						"DEVMEM",
						"ACPI_CUSTOM_METHOD",
						"COMPAT_BRK",
						"DEVKMEM",
						"COMPAT_VDSO",
						"BINFMT_MISC",
						"INET_DIAG",
						"KEXEC",
						"PROC_KCORE",
						"LEGACY_PTYS",
						"BUG_ON_DATA_CORRUPTION",
						"SCHED_STACK_END_CHECK",
						"PAGE_POISONING",
						"SLAB_FREELIST_HARDENED",
						"SLAB_FREELIST_RANDOM",
						"HARDENED_USERCOPY",
						"HARDENED_USERCOPY_FALLBACK",
						"FORTIFY_SOURCE",
						"MODULE_SIG",
						"MODULE_SIG_ALL",
						"MODULE_SIG_FORCE",
			]
	EXACT_WHITE_RULES = [
						"BUG",
						"STRICT_KERNEL_RWX",
						"STACKPROTECTOR_STRONG",
						"CC_STACKPROTECTOR_STRONG",
						"STRICT_MODULE_RWX",
						
						"PAGE_TABLE_ISOLATION",
						"RANDOMIZE_MEMORY",
						"SECURITY",
						"REFCOUNT_FULL",
						"HIGHMEM64G",
						"X86_PAE",
						"PAGE_TABLE_ISOLATION",
						"SECURITY_LOADPIN",
						"SECURITY_DMESG_RESTRICT",
						"SECCOMP",
						"SECCOMP_FILTER",
						"IO_STRICT_DEVMEM"
			]

	ARCH_EXACT_WHITE_RULES = {
				"X86_32": [
						"RANDOMIZE_BASE",
						"RETPOLINE",
						"X86_SMAP",
						"X86_INTEL_UMIP",
						"SYN_COOKIES",
						"GCC_PLUGIN_STACKLEAK",
						"STRICT_DEVMEM",
						"REFCOUNT_FULL"
					]
				}
	
	print "Architecture: %s" % arch
	
	invalid = {"remove": [], "add": []}
	
	# for c in FUZZY_BLACK_RULES:
	#	if c in config and kconfig[config] == 'y':
	#		invalid["remove"].append(config)

	for c in EXACT_BLACK_RULES:
		if c in kconfig and kconfig[c] == 'y':
			invalid["remove"].append(c)

	for c in EXACT_WHITE_RULES:
		if (c in kconfig and kconfig[c] == 'n') or (c not in kconfig):
			invalid["add"].append(c)
				
	for c in ARCH_EXACT_WHITE_RULES[arch]:
		if (c in kconfig and kconfig[c] == 'n') or (c not in kconfig):
			invalid["add"].append(c)
	return invalid

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Extract Linux kernel configuration file")
	parser.add_argument("kernel", help = "Linux Kernel File (vmlinux)")

	args = parser.parse_args()

	config = kconfig(args.kernel)
		
	parsed = parse_kconfig(config)
	
	invalid_configs = filter_kconfig(parsed)

	print "Invalid configs:"
	pprint.PrettyPrinter().pprint(invalid_configs)

	# pprint.PrettyPrinter().pprint(parsed)
