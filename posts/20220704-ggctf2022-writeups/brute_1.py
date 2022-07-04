wtf = [134, 72, 8, 237, 30, 49, 89, 229, 232, 232, 228, 17, 242, 81, 243, 1, 225, 114, 46, 224, 109, 91, 103, 182]

def swap(arr, a, b):
    tmp = arr[a]
    arr[a] = arr[b]
    arr[b] = tmp

def one_round(a, b):
    x = 0
    mem = list(range(0x100))
    tmp = [0] * 3
    for j in range(128):
        x = (x + a) & 0xff
        swap(mem, 2*j, x)
        x = (x + mem[2*j+1]) & 0xff

        x = (x + b) & 0xff
        swap(mem, 2*j+1, x)
        x = (x + mem[(2*j+2) & 0xff]) & 0xff

    x = 0
    for j in range(3):
        x = (x + mem[j]) & 0xff
        swap(mem, j, x)
        tmp[j] += mem[(mem[j] + mem[x]) & 0xff]
    
    return tmp

for i in range(0, len(wtf), 3):
    for a in range(0x21, 0x7f):
        for b in range(0x21, 0x7f):
            tmp = one_round(a, b)
            if tmp[0] == wtf[i] and tmp[1] == wtf[i+1] and tmp[2] == wtf[i+2]:
                print(chr(a) + chr(b), end='')
                