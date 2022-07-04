from z3 import *

s = Solver()

V_LEN = 12
v = [0] * V_LEN
for i in range(V_LEN):
    v[i] = BitVec("v_{}".format(i), 64)
    s.add(And(v[i] > 0x20, v[i] < 0x7f))

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


s.add(sum == 0)

sol_count = 0
solutions = []

print("Checking")

while sol_count < 5 and s.check() == sat:
    model = s.model()
    result = [model[v[i]].as_long() for i in range(V_LEN)]
    print(''.join([chr(i) for i in result]))
    solutions.append(result)
    sol_count += 1

    print("sol_count=", sol_count)

    cond = True
    for i in range(1, V_LEN):
        cond = And(cond, v[i] == result[i])

    s.add(Not(cond))

