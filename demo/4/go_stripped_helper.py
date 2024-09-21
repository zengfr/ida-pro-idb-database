#!/usr/bin/python
#
# IDA Pro script that loads symbols (function names & types) from Go-lang stripped binaries
#
# References:
#  * https://gitlab.com/zaytsevgu/goutils/blob/master/go_renamer.py
#  * https://github.com/zlowram/radare2-scripts/tree/master/go_helpers
#  * https://twitter.com/timstrazz/status/771120143686520833
# 

import re

from idc import *
from idaapi import *
from idautils import *

def get_arch_bits():
	arch = (None, None)
	info = idaapi.get_inf_structure()	

	if info.is_64bit():
		arch = (8, Qword)
	elif info.is_32bit():
		arch = (4, Dword)
	else:
		raise Exception("Invalid arch")
	return arch

def load_typelink_tab():
	segm = get_segm_by_name(".typelink")

	if not segm:
		raise Exception("Unable to find the '.typelink' segment")

	seg_ea = segm.startEA
	start, end = SegStart(seg_ea), SegEnd(seg_ea)
	print("[*] Reading .typelink segment...")

	return [PTR(addr) for addr in xrange(start, end, PTR_SIZE)]

def go_fnc_renamer():
	segm = get_segm_by_name(".gopclntab")

	if not segm:
		raise Exception("Unable to find the '.gopclntab' segment")

	base = segm.startEA
	pos  = base + 8 # skip segment header
	count = 0

	size =  PTR(pos)
	pos  += PTR_SIZE
	end  =  pos + (size * PTR_SIZE * 2)

	print("[*] Reading .gopclntab segment...")

	while pos < end:
		offset      =  PTR(pos + PTR_SIZE)
		pos         += PTR_SIZE * 2
		fcn_addr    =  PTR(base + offset)
		name_offset =  Dword(base + offset + PTR_SIZE)
		name        =  GetString(base + name_offset)
		clean_name  =  re.sub("[^a-zA-Z0-9\n\.]", "_", name)

		MakeNameEx(fcn_addr, name, idc.SN_WEAK)
		count += 1

	print("[+] Found and renamed %d functions!" % count)

def go_load_types():
	count = 0
	typelink_tab = load_typelink_tab()
	str_offset = 24 if PTR_SIZE == 4 else 40

	for type_ea in typelink_tab:
		off  = PTR(type_ea + str_offset)
		off2 = PTR(off)
		strz = PTR(off + PTR_SIZE)
		sym  = GetManyBytes(off2, strz)

		MakeRptCmt(type_ea, sym)
		count += 1	

	print("[+] Loaded %s type references!" % count)

if __name__ == '__main__':	
	try:
		PTR_SIZE, PTR = get_arch_bits()
		go_fnc_renamer()
		go_load_types()

	except Exception, e:
		warning("ERROR: %s" % e)

