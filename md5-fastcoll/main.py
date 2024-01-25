import random
import sys
from datetime import datetime

import block0
import block1
import md5
import hashlib
import os
import time
from multiprocessing import Pool, cpu_count

MD5IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
collision_count = 0  # ulong
time3 = time4 = time5 = 0  # double
now = datetime.now().strftime("%d%m%Y-%H%M%S")

def main():
    newDir = os.path.join(os.getcwd(), "collisions")

    try:
        if not os.path.exists(newDir):
            os.makedirs(newDir)
    except OSError:
        sys.exit(f"Fatal: output directory {newDir} does not exist and cannot be created")
    filePath = os.path.join(newDir, f"collisions_{now}.txt")
    with open(filePath, "a+") as file:
        file.write(f"Starting time: {datetime.now().strftime('%d.%m.%Y-%H:%M:%S')}\n")
        file.close()

    cpuCount = int(cpu_count() * 0.9)
    seeds = [None] * cpuCount
    if len(sys.argv) > 1 and type(int(sys.argv[1])) is int:
        seedStep = int(sys.argv[1])
        seeds = [((i + 1) * seedStep) for i in range(cpuCount)]
    print(f"Starting with RNG seeds {seeds}")
    with Pool(cpuCount) as p:
        p.map(find_collision, seeds)
        p.terminate()


def find_collision(seed):
    random.seed(seed)
    IV = MD5IV.copy()
    while True:
        filePath = os.path.join(os.getcwd(), "collisions", f"state_{now}.txt")
        with open(filePath, "a+") as file:
            file.write(f"{os.getpid()} @ {datetime.now().strftime('%d.%m.%Y-%H:%M:%S')}: state is {random.getstate()}\n\n")
            file.close()

        IV0 = IV.copy()

        startTime = time.perf_counter()
        print("Searching first block: ")
        block0result = block0.find_block0(IV)
        time1 = time.perf_counter() - startTime

        msg1_block0 = block0result[0]
        Q = block0result[1]

        IV = md5.compress(IV, msg1_block0)

        block1result = block1.find_block1(IV)
        time2 = time.perf_counter() - time1 - startTime

        global collision_count, time3, time4, time5
        collision_count += 1
        time3 += time1 + time2
        time4 += time1
        time5 += time2

        msg1_block1 = block1result[0]
        hashDigest = block1result[1]
        Q2 = block1result[2]


        msg2_block0 = msg1_block0.copy()
        msg2_block1 = msg1_block1.copy()

        # print(msg2_block0)
        # print(msg2_block1)
        msg2_block0[4] = (msg2_block0[4] + (1 << 31)) & 0xFFFFFFFF
        msg2_block0[11] = (msg2_block0[11] + (1 << 15)) & 0xFFFFFFFF
        msg2_block0[14] = (msg2_block0[14] + (1 << 31)) & 0xFFFFFFFF
        msg2_block1[4] = (msg2_block1[4] + (1 << 31)) & 0xFFFFFFFF
        msg2_block1[11] = (msg2_block1[11] - (1 << 31)) % (1 << 32)
        msg2_block1[14] = (msg2_block1[14] + (1 << 31)) & 0xFFFFFFFF

        print("Found collision, saving...")

        result = [f"{os.getpid()} @ {datetime.now().strftime('%d.%m.%Y-%H:%M:%S')}",
                  f"IV: {', '.join('0x{:08x}'.format(num) for num in IV0)}",
                  f"Hash digest: {', '.join('0x{:08x}'.format(num) for num in hashDigest)}",
                  f"m1: {', '.join('0x{:08x}'.format(num) for num in msg1_block0)}, {', '.join('0x{:08x}'.format(num) for num in msg1_block1)}",
                  f"m2: {', '.join('0x{:08x}'.format(num) for num in msg2_block0)}, {', '.join('0x{:08x}'.format(num) for num in msg2_block1)}",
                  f"Q: {', '.join('0x{:08x}'.format(num) for num in Q)}",
                  f"Q2: {', '.join('0x{:08x}'.format(num) for num in Q2)}",
                  f"1st block: {time1}",
                  f"2nd block: {time2}",
                  f"AVERAGE 1st block: {time4 / collision_count}",
                  f"AVERAGE 2nd block: {time5 / collision_count}",
                  f"AVERAGE time for {collision_count} collisions: {time3 / collision_count}"]

        filePath = os.path.join(os.getcwd(), "collisions", f"collisions_{now}.txt")
        with open(filePath, "a+") as file:
            file.write(f"{result}\n")
            file.close()



if __name__ == '__main__':
    main()
    # test()
