from ida_bytes import get_bytes, patch_bytes
import re

from capstone import *

REG_S = None
REG_D = None


def dism(code):
	global REG_S, REG_D
	ARCH = CS_ARCH_ARM
	MODE = CS_MODE_THUMB
	OFFSET = 0x0

	CODE = bytes(code)

	cs = Cs(ARCH, MODE)

	for i in cs.disasm(CODE,OFFSET):
		print("%s%s" %(i.mnemonic, i.op_str))
		if 'push' in i.mnemonic:
			REG_S = i.op_str[1:-1]
		else:
			REG_D = i.op_str[1:-1]
	
			
from keystone import *

def asm(dism_str):
	# separate assembly instructions by ; or \n
#	CODE = b"push {r0};pop {r1}"
	CODE = dism_str
	try:
		# Initialize engine in X86-32bit mode
		ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
		encoding, count = ks.asm(CODE)
#		print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
		return encoding
	except KsError as e:
		print("ERROR: %s" %e)			
	

def print_bytes(bytes_str):
	print ' '.join(hex(ord(c)) for c in bytes_str)

startAddr = 0x1E50
endAddr = 0x20B4    
buf = get_bytes(startAddr, endAddr-startAddr)
print("==================deflower================")
#print_bytes(buf)

def handler(s):
	global REG_D, REG_S
	print("-------------Found-----------")
	g0 = s.group(0)
	print("---->Orig bytes and assemble")
	print_bytes(g0)
	dism(g0)
	
	print(REG_D, REG_S)
	print("---->Replace bytes and assemble")
	dism_str = "mov {},{}".format(REG_D, REG_S)
	print(dism_str+'\nnop')
	mov_encode = asm(dism_str)
	nop_encode = asm('nop')
	replace_encode = mov_encode + nop_encode
	
	print [hex(b) for b in replace_encode]
	r = bytearray(replace_encode)
	print(r, type(r))
	return str(r)

pattern = r'[\x00-\xFF]\xB4[\x00-\xFF]\xBC'

buf = re.sub(pattern, handler, buf, flags=re.I)

#print_bytes(buf)

# patch 
patch_bytes(startAddr, buf)


		
	