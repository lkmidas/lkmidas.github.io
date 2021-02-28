from malduck import *

#key = b"\x42\x8C\x81\xC5\xEA\x13\xE0\xC2\x15\x5C\x43\x1D\x54\xB5\x99\xAA\x2D\x27\x57\x1A\x26\x5B\x6D\x00\x68\xC9\x4B\xF4\x80\xBA\xCA\x5E"

key = open("./dump", "rb").read()[0x4ba74:0x4ba74+0x20]

encrypted = ida_bytes.get_bytes(0x13a9, 896)

decrypted = xor(key, encrypted)

ida_bytes.patch_bytes(0x13a9, decrypted)
