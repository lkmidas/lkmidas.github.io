v = b"abcdefghijkl"

consts = [0xffffffffffff2664, 0xfffffffffffeae0c, 0xffffffffffff36ed, 0xfffffffffffe82d5, 0xfffffffffffe6984, 0xfffffffffffdf521, 0xfffffffffffe7f1e, 0xfffffffffffe56e1, 0xfffffffffffefff1, 0xffffffffffff1002, 0xffffffffffff0b7f, 0xfffffffffffec4b9, 0xfffffffffffe8118, 0xfffffffffffeaca5, 0xffffffffffff87af, 0xffffffffffffa4d9, 0xfffffffffffe3e11]
sum = 0

eq = open("eq.txt", "r").read().split("\n")
count_v = 0
count_x = 0
x = consts[0]

for line in eq:

    if len(line) == 0:
        sum = sum + (x & 0xffffff)
        count_v = 0
        count_x += 1
        x = consts[count_x]
        continue

    if line.startswith("AND"):
        x += v[count_v] & int(line.split(' ')[-1])
    elif line.startswith("OR"):
        x += v[count_v] | int(line.split(' ')[-1])
    elif line.startswith("XOR"):
        x += v[count_v] ^ int(line.split(' ')[-1])
    elif line.startswith("SHL"):
        x += (v[count_v] << int(line.split(' ')[-1])) & 0xff
    elif line.startswith("SHR"):
        x += v[count_v] >> int(line.split(' ')[-1])
    elif line.startswith("ROL"):
        x += ((v[count_v] << (int(line.split(' ')[-1]) % 8)) & 0xff) | ((v[count_v] >> (8 - int(line.split(' ')[-1]) % 8) & 0xff))
    elif line.startswith("ROR"):
        x += ((v[count_v] >> (int(line.split(' ')[-1]) % 8)) & 0xff) | ((v[count_v] << (8 - int(line.split(' ')[-1]) % 8) & 0xff))
    else:
        x = (x + v[count_v] * int(line.split(' ')[-1])) & 0xffffffffffffffff
    count_v += 1

print(hex(sum))



