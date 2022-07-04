code = open("opcode2.txt", "r").read().split('\n')

target = 0
eq = 0
var = 0
found = 0
count = 0
base = 0
consts = []
for i in range(len(code)):
    line = code[i]

    if "VAL_G \t<- ffffff" in line:
        consts.append(hex(int(line[-16:], 16)))
        if found == 0 and count != 0:
            mult = int(code[i-10].split(' ')[-1], 16) // base
            print(mult)
        if count != 0:
            print()
        count += 1

    if "VAL_B \t<- 40405" in line:
        var_addr = int(line[-6:], 16)
        if found == 0 and var_addr != 0x404050:
            mult = int(code[i-2].split(' ')[-1], 16) // base
            print(mult)
        found = 0
        try:
            base = int(code[i+11].split(' ')[-1], 16)
        except:
            base = 0

    if "SHELLCODE" in line:
        shellcode = bytes.fromhex(code[i-4].split(' ')[-1].zfill(16))[::-1]
        val = shellcode[7]
        op = shellcode[0] + (shellcode[1] << 8)
        if op == 0x2480:
            print("AND", val)
        elif op == 0x04c0:
            print("ROL", val)
        elif op == 0x0c80:
            print("OR", val)
        elif op == 0x2cc0:
            print("SHR", val)
        elif op == 0x24c0:
            print("SHL", val)
        elif op == 0x3480:
            print("XOR", val)
        elif op == 0x0cc0:
            print("ROR", val)
        else:
            print(229)
            break
        found = 1


for i in consts:
    print(i, end=', ')
