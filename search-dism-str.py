#!/usr/bin/python

from idaapi import *
import idc
import idautils

def lookup_str_in_func(func):
	found = []
	addrs = list(idautils.FuncItems(func)) # get list of all the address
	for line in addrs:
	    dism = idc.generate_disasm_line(line, 0)
	    if input_str in dism:
	    	find_item = hex(line)[:-1] + "\t"
	    	find_item += dism

	    	found.append(find_item)

	for one in found:
		print(one)

print("-------------- [xda] finDismStrInAllfunc --------------")

input_str = idc.AskStr("", "Input string of searching:")

if not input_str or input_str == "":
	print("please input the string.")
else:
	for func in idautils.Functions():
		flags = idc.get_func_attr(func, FUNCATTR_FLAGS) 
		if flags & FUNC_LIB or flags & FUNC_THUNK:
			continue
		lookup_str_in_func(func)	
print("--------------------------------------------------------")






















