data = open("eldar", "rb").read()

start = 0xa45b1a - 0x800000
end = 0x259d3a

new_data = data[:start] + b"\0"*(end-start) + data[end:]

open("eldar-test", "wb").write(new_data)