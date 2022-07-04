code = open("opcode1.txt", "r").read().split('\n')

target = 0
eq = 0
var = 0
count = 0
base = 0
consts = []
for i in range(len(code)):
    line = code[i]

    if "VAL_G \t<- ffffff" in line:
        consts.append(hex(int(line[-16:], 16)))
        count += 1

    if "VAL_B \t<- 804a" in line:
        var_addr = int(line[-6:], 16)
        if var_addr != 0x804aca:
            if base == 0:
                mult = 0
            else:
                mult = int(code[i-2].split(' ')[-1], 16) // base
            print(mult, end=', ')
        base = int(code[i+11].split(' ')[-1], 16)

    if "VAL_D \t<- VAL_D" in line:
        mult = int(code[i-8].split(' ')[-1], 16) // base
        print(mult)

for i in consts:
    print(i, end=', ')
print()
