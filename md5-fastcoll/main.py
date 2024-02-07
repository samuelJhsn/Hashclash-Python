import random
import sys
from datetime import datetime

import block0
import block1
import md5
import os
import time
from multiprocessing import Pool, cpu_count

MD5IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
collision_count = 0
time_blocks_cumulative = time_block0_cumulative = time_block1_cumulative = 0
now = datetime.now().strftime("%d%m%Y-%H%M%S")


def main():
    # Create dir and file for collision logging
    newDir = os.path.join(os.getcwd(), "collisions")
    try:
        if not os.path.exists(newDir):
            os.makedirs(newDir)
    except OSError:
        sys.exit(f"Output directory {newDir} does not exist and cannot be created")

    filePath = os.path.join(newDir, f"collisions_{now}.txt")
    with open(filePath, "a+") as file:
        file.write(f"Starting time: {datetime.now().strftime('%d.%m.%Y-%H:%M:%S')}\n")
        file.close()

    # Use 90% of all CPU cores for multithreaded collision finding, possibly with given seed
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
    while True:
        # Create file for RNG state logging
        filePath = os.path.join(os.getcwd(), "collisions", f"state_{now}.txt")
        with open(filePath, "a+") as file:
            file.write(
                f"{os.getpid()} @ {datetime.now().strftime('%d.%m.%Y-%H:%M:%S')}: state is {random.getstate()}\n\n")
            file.close()

        IV = [random.randint(0, (2 ** 32) - 1),
              random.randint(0, (2 ** 32) - 1),
              random.randint(0, (2 ** 32) - 1),
              random.randint(0, (2 ** 32) - 1)]
        IV0 = IV.copy()

        startTime = time.perf_counter()
        print("Searching first block: ")
        block0result = block0.find_block0(IV)
        time_block0 = time.perf_counter() - startTime

        block0_msg1 = block0result[0]
        Q0 = block0result[1]

        IV = md5.compress(IV, block0_msg1)

        block1result = block1.find_block1(IV)
        time_block1 = time.perf_counter() - time_block0 - startTime

        block1_msg1 = block1result[0]
        hashDigest = block1result[1]
        Q1 = block1result[2]
        bitCondID = block1result[3]

        block0_msg2 = block0_msg1.copy()
        block1_msg2 = block1_msg1.copy()

        block0_msg2[4] = (block0_msg2[4] + (1 << 31)) & 0xFFFFFFFF
        block0_msg2[11] = (block0_msg2[11] + (1 << 15)) & 0xFFFFFFFF
        block0_msg2[14] = (block0_msg2[14] + (1 << 31)) & 0xFFFFFFFF
        block1_msg2[4] = (block1_msg2[4] + (1 << 31)) & 0xFFFFFFFF
        block1_msg2[11] = (block1_msg2[11] - (1 << 31)) % (1 << 32)
        block1_msg2[14] = (block1_msg2[14] + (1 << 31)) & 0xFFFFFFFF

        global collision_count, time_blocks_cumulative, time_block0_cumulative, time_block1_cumulative
        collision_count += 1
        time_blocks_cumulative += time_block0 + time_block1
        time_block0_cumulative += time_block0
        time_block1_cumulative += time_block1

        print("Found collision, saving...")
        result = [f"{os.getpid()} @ {bitCondID} @ {datetime.now().strftime('%d.%m.%Y-%H:%M:%S')}",
                  f"IV: {', '.join('0x{:08x}'.format(num) for num in IV0)}",
                  f"Hash digest: {', '.join('0x{:08x}'.format(num) for num in hashDigest)}",
                  f"m1: {', '.join('0x{:08x}'.format(num) for num in block0_msg1)}, {', '.join('0x{:08x}'.format(num) for num in block1_msg1)}",
                  f"m2: {', '.join('0x{:08x}'.format(num) for num in block0_msg2)}, {', '.join('0x{:08x}'.format(num) for num in block1_msg2)}",
                  f"Q0: {', '.join('0x{:08x}'.format(num) for num in Q0)}",
                  f"Q1: {', '.join('0x{:08x}'.format(num) for num in Q1)}",
                  f"1st block: {time_block0}",
                  f"2nd block: {time_block1}",
                  f"AVERAGE 1st block: {time_block0_cumulative / collision_count}",
                  f"AVERAGE 2nd block: {time_block1_cumulative / collision_count}",
                  f"AVERAGE time for {collision_count} collisions: {time_blocks_cumulative / collision_count}"]

        filePath = os.path.join(os.getcwd(), "collisions", f"collisions_{now}.txt")
        with open(filePath, "a+") as file:
            file.write(f"{result}\n")
            file.close()


if __name__ == '__main__':
    main()
