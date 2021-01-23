from Crypto.Cipher import AES

key = b"P4nd`p<c8gE;T$F8"
encrypt = open("./encrypted.bin", "rb").read()
cipher = AES.new(key, AES.MODE_ECB)
open("out.png","wb").write(cipher.decrypt(encrypt))
