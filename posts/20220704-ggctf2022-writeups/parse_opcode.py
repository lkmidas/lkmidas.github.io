from z3 import *

data = open("eldar", "rb").read()
mem = [b for b in b'\0'*0x804000 + data[0x4000:0x25a000]]

def write64(addr, val):
    for i in range(8):
        mem[addr+i] = (val >> (8*i)) & 0xff

def write32(addr, val):
    for i in range(4):
        mem[addr+i] = (val >> (8*i)) & 0xff

def writen(addr, val, n):
    for i in range(n):
        mem[addr+i] = (val >> (8*i)) & 0xff

def read64(addr):
    r = 0
    for i in range(8):
        r += (mem[addr+i] << (8*i))
    return r

def readn(addr, n):
    r = 0
    for i in range(n):
        r += (mem[addr+i] << (8*i))
    return r

for i in range(28):
    mem[0x404040 + i] = 0x61 + i

pc = 0x8042ba
dynsym = 0x80406c
regs = {}

for i in range(1, 11):
    regs[dynsym + i*24] = "VAL_" + chr(ord('A') + i - 1)
    regs[dynsym + 8 + i*24] = "LEN_" + chr(ord('A') + i - 1)
    regs[dynsym - 8 + i*24] = "TYPE_" + chr(ord('A') + i - 1)

shellcode = open("shell.bin", "wb")

while pc < 0xa5a000:
    print("{:08x}: ".format(pc), end="")

    # if pc == 0x00a57b02:
    #     print(hex(read64(0x8040ac)))
    #     break

    r_offset = read64(pc)
    r_type = read64(pc+8) & 0xffff
    r_sym = read64(pc+8) >> 32
    r_addend = read64(pc+16)

    print_offset = hex(r_offset)[2:]
    print_addend = hex(r_addend)[2:]
    if r_offset in regs:
        print_offset = regs[r_offset]
    if r_addend in regs:
        print_addend = "&" + regs[r_addend]

    sym_addr = dynsym + r_sym*24

    if r_type == 8:
        write64(r_offset, r_addend)
        #print("RELA\t{}\t{:x}".format(print_offset, r_addend))
        print("{} \t<- {}".format(print_offset, print_addend))
    elif r_type == 5:
        sym_len = read64(sym_addr + 8)
        writen(r_offset, r_addend + readn(read64(sym_addr), sym_len), sym_len)
        #print("COPY\t{}\t{}\t{:x}".format(print_offset, regs[sym_addr], r_addend))
        print("{} \t<- [{} + {}]".format(print_offset, regs[sym_addr], print_addend))
    elif r_type == 1:
        if read64(0x8040ac) == 0x1000a0000001a and r_sym == 3:
            shell_len = read64(pc+24*2+16)
            shell_addr = read64(0x8040b4)
            shellcode.write(bytes(mem[shell_addr:shell_addr+shell_len]))
            write64(r_offset, 0)
            #print("__64\t{}\t{}\t{:x} SHELLCODE".format(print_offset, regs[sym_addr], r_addend))
            print("{} \t<- SHELLCODE".format(print_offset))
        else:
            write64(r_offset, r_addend + read64(sym_addr))
            #print("__64\t{}\t{}\t{:x}".format(print_offset, regs[sym_addr], r_addend))
            print("{} \t<- {} + {}".format(print_offset, regs[sym_addr], print_addend))
    elif r_type == 0xa:
        write32(r_offset, r_addend + read64(sym_addr))
        #print("__32\t{}\t{}\t{:x}".format(print_offset, regs[sym_addr], r_addend))
        print("{} \t<- DWORD({} + {})".format(print_offset, regs[sym_addr], print_addend))
    elif r_type == 0:
        break
    else:
        print("UNKNOWN R_TYPE")
        break

    pc += 24
