from malduck import *

data = open("./dump", "rb").read()[0x5060:0x5b6e0]

enc_flag = data[:0x80]

candidate = b""
key_iv = []
x = 0
while x < len(data) - 0x10:
    candidate = data[x:x+0x10]
    if data.count(candidate) > 1:
        key_iv.append(candidate)
    x += 1

#print(aes.cbc.decrypt(key_iv[0], key_iv[1], enc_flag))
print(aes.cbc.decrypt(key_iv[1], key_iv[0], enc_flag))

