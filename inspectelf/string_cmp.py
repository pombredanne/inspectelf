from elftools.elf.elffile import ELFFile
import itertools
import operator

ignore_strings = [
	".ARM.attributes",
	".bss",
	".comment",
	".data",
	".data.rel.ro",
	".divsi3_skip_div0_test",
	".dynamic",
	".dynstr",
	".dynsym",
	".eh_frame",
	".fini",
	".fini_array",
	".gnu.attributes",
	".gnu.hash",
	".gnu.version",
	".gnu.version_r",
	".hash",
	".init",
	".init_array",
	".mdebug.abi32",
	".MIPS.abiflags",
	".note.GNU-stack",
	".note.gnu.build-id",
	".reginfo",
	".rel.data.rel.local",
	".rel.dyn",
	".rel.pdr",
	".rel.plt",
	".rel.text",
	".rela.data.rel.local",
	".rela.eh_frame",
	".rela.text",
	".rodata",
	".sdata",
	".shstrtab",
	".strtab",
	".symtab",
	".text",
	".udivsi3_skip_div0_test",
	"__adddf3",
	"__aeabi_cdcmpeq",
	"__aeabi_cdcmple",
	"__aeabi_cdrcmple",
	"__aeabi_d2iz",
	"__aeabi_dadd",
	"__aeabi_dcmpeq",
	"__aeabi_dcmpge",
	"__aeabi_dcmpgt",
	"__aeabi_dcmple",
	"__aeabi_dcmplt",
	"__aeabi_ddiv",
	"__aeabi_dmul",
	"__aeabi_drsub",
	"__aeabi_dsub",
	"__aeabi_f2d",
	"__aeabi_i2d",
	"__aeabi_idiv",
	"__aeabi_idiv0",
	"__aeabi_idivmod",
	"__aeabi_l2d",
	"__aeabi_ldiv0",
	"__aeabi_ui2d",
	"__aeabi_uidiv",
	"__aeabi_uidivmod",
	"__aeabi_ul2d",
	"__bss_end__",
	"__bss_start",
	"__bss_start__",
	"__clzsi2",
	"__cmpdf2",
	"__ctzsi2",
	"__cxa_finalize",
	"__cxa_finalize@@GLIBC_2.4",
	"__divdf3",
	"__divsi3",
	"__do_global_dtors_aux",
	"__do_global_dtors_aux_fini_array_entry",
	"__dso_handle",
	"__end__",
	"__eqdf2",
	"__extendsfdf2",
	"__fixdfsi",
	"__floatdidf",
	"__floatsidf",
	"__floatundidf",
	"__floatunsidf",
	"__frame_dummy_init_array_entry",
	"__FRAME_END__",
	"__gedf2",
	"__gmon_start__",
	"__gtdf2",
	"__JCR_END__",
	"__JCR_LIST__",
	"__ledf2",
	"__ltdf2",
	"__muldf3",
	"__nedf2",
	"__subdf3",
	"__TMC_END__",
	"__udivsi3",
	"_bss_end__",
	"_DYNAMIC",
	"_edata",
	"_fbss",
	"_fdata",
	"_fini",
	"_ftext",
	"_GLOBAL_OFFSET_TABLE_",
	"_gp_disp",
	"_init",
	"_ITM_deregisterTMCloneTable",
	"_ITM_registerTMCloneTable",
	"_Jv_RegisterClasses",
	"deregister_tm_clones",
	"GLIBC_2.4",
	"register_tm_clones",
]

# Retrieves readable strings from a (section of an ELF) file
def read_strings(f, section = None):
	i = 0
	inString = False
	curStr = bytearray('')
	try:
		f = open(f, 'rb')
		if section is not None:
			offset = section.header.sh_offset
			size = section.header.sh_size
			f.seek(offset)
		byte = f.read(1)
		while byte != "" and f.tell() < offset + size:
			# Between space and tilde (i.e printable and non-special)
			if ord(byte) >= 0x20 and ord(byte) < 0x7F:
				if not inString:
					# Skip whitespace at start of strings?
					#while byte in string.whitespace:
					#   byte = f.read(1)

					# We're in a new string
					inString = True

					# Yield the latest string
					if str(curStr) not in ignore_strings:
						yield str(curStr)

					curStr = bytearray('')

				curStr.append(byte)
			else:
				inString = False

			byte = f.read(1)

		# Return the final string, if needed
		if inString and str(curStr) not in ignore_strings:
			yield str(curStr)

		f.close()
	except IOError:
		pass

# Returns strings of appropriate minimum length, sorted and unique
def get_strings(f, section, minLength=5):
	# fast generator-friendly version of uniq+sort
	# from http://stackoverflow.com/questions/2931672/
	def sort_uniq(sequence):
		return itertools.imap(
			operator.itemgetter(0),
			itertools.groupby(sorted(sequence)))

	return sort_uniq(itertools.ifilter(lambda s: len(s) >= minLength,
					   read_strings(f, section)))

def string_scan(elffile):
	strs = {}

	with open(elffile, "rb") as fp:
		elf = ELFFile(fp)
		sections = ('.dynstr', '.rodata', '.data', '.strtab')

		for section in elf.iter_sections():
			if section.name in sections:
				strs[section.name] = list(get_strings(elffile, section))

	return strs
