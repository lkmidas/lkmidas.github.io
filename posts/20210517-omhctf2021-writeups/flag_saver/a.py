from PIL import Image
from copy import deepcopy

class LCG:
    def __init__(self, seed, modulus):
        self.seed = seed
        self.modulus = modulus
        self.a = 57005
        self.c = 48879

    def next_value(self):
        self.seed = (self.a * self.seed + self.c) % self.modulus
        return self.seed


pieces = 120
M = 16
N = 9
lcg = LCG(51966, 128)
shuffle_list = []


def shuffle():
    result = []
    num = pieces * pieces
    lCG = LCG(lcg.next_value(), 65537)
    for i in range(pieces):
        for j in range(pieces):
            num1 = lCG.next_value() % num
            num2 = lCG.next_value() % num
            result.append((num1, num2))
    return result


for i in range(10):
    shuffle_list.append(shuffle()[::-1])

im = Image.open("screenshot.png")
imgarray = [im.crop((x, y, x+M, y+N)) for x in range(0, im.size[0], M) for y in range(0, im.size[1], N)]


def rearrange_one_tick(a, s):
    for i in range(len(s)):
        tmp = a[s[i][0]]
        a[s[i][0]] = a[s[i][1]]
        a[s[i][1]] = tmp
    return a


def save_image(a, n):
    new_im = Image.new('RGBA', (1920, 1080), (255, 255, 255, 255))
    for i in range(len(a)):
        offset = ((i // pieces) * M, (i % pieces) * N)
        new_im.paste(a[i], offset)
    new_im.save("./results/result_{}.png".format(n))


def rearrange(tick_cnt):
    newarray = deepcopy(imgarray)
    new_array = rearrange_one_tick(newarray, shuffle_list[tick_cnt - 1])
    save_image(newarray, tick_cnt)



for i in range(1, 10):
    rearrange(i)
