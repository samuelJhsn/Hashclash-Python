import random
import block0
import md5
import hashlib
from multiprocessing import Pool, cpu_count

MD5IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def test():
    ihv = MD5IV.copy()
    input = "a"
    inputInt = int.from_bytes(str.encode(input), "big")
    # ihv = md5.digest(ihv, inputInt)
    print(list(map(hex, md5.compress(ihv, [1133, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))))
    # print(list(map(hex, ihv)))

    print(hashlib.md5().hexdigest())


def main():
    IV = MD5IV.copy()
    cpuCount = int(cpu_count() / 2)
    with Pool(cpuCount) as p:
        p.map(find_collision, [IV] * cpuCount)


def find_collision(IV):
    print("Generating first block: ")
    msg1_block0 = block0.find_block0(IV)
    #
    # print("Generating second block: ")
    # msg1_block1 = block1.find_block1(IV)
    #
    # msg2_block0 = msg1_block0.copy()
    # msg2_block1 = msg1_block1.copy()
    #
    # msg2_block0[4] += 1 << 31
    # msg2_block0[11] += 1 << 15
    # msg2_block0[14] += 1 << 31
    # msg2_block1[4] += 1 << 31
    # msg2_block1[11] -= 1 << 15
    # msg2_block1[14] += 1 << 31

    print("DONE!!!")
    # return [(msg1_block0, msg1_block1), (msg2_block0, msg2_block1)]


if __name__ == '__main__':
    main()
    #test()
