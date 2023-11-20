import csv
import hashlib
import os
import random
import time
from datetime import datetime
import re
import numpy as np
import sys
from multiprocessing import Pool, cpu_count
import math
import textwrap
from operator import add
import matplotlib.pyplot as plt


def getHashes(compRoomStart, compRoomEnd, hashFunction):
    startGenBits = time.perf_counter()

    randomBitString = True
    bitStrings = []
    if randomBitString:
        for _ in range(compRoomStart, compRoomEnd):
            randomNumba = random.randint(0, 2 ** 445)
            bitStrings.append(randomNumba.to_bytes(math.ceil(randomNumba.bit_length() / 8), byteorder='big'))
    else:
        bitStrings = [e.to_bytes(math.ceil(e.bit_length() / 8), byteorder='big')
                      for e in range(compRoomStart, compRoomEnd)]
    endGenBits = time.perf_counter()

    startHashing = time.perf_counter()

    hashes = [hashFunction(bitString).hexdigest() for bitString in bitStrings]
    hashes = [list(f'{int(h, 16):0>{8 * hashFunction().digest_size}b}') for h in hashes]
    hashes = [[int(numba) for numba in h] for h in hashes]
    endHashing = time.perf_counter()

    return hashes


def getBitDistribution(hashes, hashFunction):
    bitDistribution = [0 for _ in range(8 * hashFunction().digest_size + 1)]

    startBitCount = time.perf_counter()

    for h in hashes:
        bitDistribution = list(map(add, bitDistribution, h))
    endBitCount = time.perf_counter()

    # print(f"Took {endBitCount - startBitCount} seconds to count "
    #      f"{8 * hashlib.md5().digest_size * len(hashes)} bits in all hashes.")

    return bitDistribution


def getRandomWalkStats(hashes, hashFunction):
    bitsPerHash = 8 * hashFunction().digest_size
    hashesRandWalk = [[h, bitsPerHash / 2 - sum(h)]
                      for h in hashes]  # Map each hash to pair (itself, hashlength - N of 1-bits)
    oldDir = os.getcwd()
    newDir = os.getcwd() + "\\randomWalks"
    if not os.path.exists(newDir):
        os.makedirs(newDir)
    os.chdir(newDir)

    timeStamp = datetime.now().strftime("%H_%M_%S_")
    plt.figure(timeStamp)
    ax = plt.gca()
    ax.set_ylim([-bitsPerHash // 3, bitsPerHash // 3])
    plt.xlabel("bit position")
    plt.ylabel("cumulative bit value")

    allMaxY = []
    allMinY = []
    allZeroPos = []
    endPoints = []
    xPos = [i for i in range(bitsPerHash + 1)]
    for i, pair in enumerate(hashesRandWalk):
        y = 0
        maxY = 0
        minY = 0
        zeroPos = []
        yPos = [0]
        for j, bit in enumerate(pair[0]):
            if y == 0:
                zeroPos += [xPos[j]]
            y += (int(bit) * 2 - 1)
            if maxY < y:
                maxY = y
            if minY > y:
                minY = y
            yPos.append(y)

        endPoints += [y]
        allMaxY += [maxY]
        allMinY += [minY]
        allZeroPos += zeroPos
        plt.figure(timeStamp + str(i))
        ax = plt.gca()
        ax.set_ylim([-bitsPerHash // 3, bitsPerHash // 3])
        plt.xlabel("bit position")
        plt.ylabel("cumulative bit value")
        plt.plot(xPos, yPos)
        # plt.scatter(zeroPos, [0] * len(zeroPos), marker="o")
        plt.scatter(zeroPos * 2, [ax.get_ylim()[0] // 10] * len(zeroPos) + [ax.get_ylim()[1] // 10] * len(zeroPos),
                    marker="o")

        plt.savefig(timeStamp + str(i))

        plt.figure(timeStamp)
        plt.plot(xPos, yPos)
        plt.scatter(zeroPos, [-40] * len(zeroPos), marker="o")
        # print(zeroPos)
        pair += [zeroPos]

    plt.figure(timeStamp)
    plt.savefig(timeStamp)
    print(np.mean(allZeroPos[:10]))
    randomWalkStats = [('%.1f' % (np.mean(allZeroPos[:10]))), min(allMinY), max(allMaxY), ('%.4f' % (np.mean(endPoints)))]

    os.chdir(oldDir)

    return randomWalkStats


# warnings.filterwarnings("ignore")
# @jit(target_backend='cuda', nopython=False)
def main():
    try:
        if sys.argv[1].lower() not in hashlib.algorithms_guaranteed:
            print(f"Try again with a valid hash function out of: {hashlib.algorithms_guaranteed}")
            sys.exit(1)
        match sys.argv[1]:
            case "md5":
                hashFunction = hashlib.md5
            case "sha1":
                hashFunction = hashlib.sha1
            case "sha224":
                hashFunction = hashlib.sha224
            case "sha256":
                hashFunction = hashlib.sha256
            case "sha384":
                hashFunction = hashlib.sha384
            case "sha512":
                hashFunction = hashlib.sha512
            case "shake_128":
                hashFunction = hashlib.shake_128
            case "shake_256":
                hashFunction = hashlib.shake_256
            case "blake2b":
                hashFunction = hashlib.blake2b
            case "blake2s":
                hashFunction = hashlib.md5
            case "sha3_224":
                hashFunction = hashlib.sha3_224
            case "sha3_256":
                hashFunction = hashlib.sha3_256
            case "sha3_384":
                hashFunction = hashlib.sha3_384
            case _:
                hashFunction = hashlib.sha3_512
    except IndexError as indErr:
        print(f"{indErr}: Expected first argument out of: {hashlib.algorithms_guaranteed}")
        sys.exit(1)
    try:
        cpuCount = cpu_count() // 2
        compRooms = getCompRooms(0, int(sys.argv[2]), cpuCount)
    except ValueError as valErr:
        print(f"{valErr}: Expected int, found {type(sys.argv[2])}")
        sys.exit(1)
    except IndexError as indErr:
        print(f"{indErr}: Expected second argument")
        sys.exit(1)

    start = time.perf_counter()

    with Pool(cpuCount) as p:
        hashingParams = [tup + (hashFunction,) for tup in compRooms]
        print(f"Generating {compRooms[0][1]} {sys.argv[1]} hashes in each of {cpuCount} processes, please "
              f"wait...")
        hashes = p.starmap(getHashes, hashingParams)
        statParams = [(partOfHashes, hashFunction,) for partOfHashes in hashes]

        # distribution = p.starmap(getBitDistribution, statParams)
        randWalkStats = p.starmap(getRandomWalkStats, statParams)

    # distribution = [sum(x) for x in zip(*distribution)]

    # np.savetxt("distribution.csv",
    #            distribution,
    #            delimiter=", ",
    #            fmt="% s")
    with open("randomWalkStats.csv", "w") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerows(randWalkStats)

    end = time.perf_counter()
    print(f"Took {end - start} seconds to process {2 ** int(sys.argv[2])} values in {cpuCount} processes")


def getCompRooms(minPower=0, maxPower=0, cpuCount=1):
    """
    Computes and returns a list of intervals with size (2 ** maxPower) - (2 ** minPower) to be used for hash computation

    Parameters:
    minPower (int): lower power used to calculate lower computation room, default 0
    maxPower (int): upper power used to calculate upper computation room, default 0

    Returns:
    list of intervals equal to the number of available cpu cores
    """
    if minPower < 0:
        minPower *= 1
    if maxPower < 0:
        maxPower *= 1
    if minPower >= maxPower:
        minPower, maxPower = maxPower, minPower
    hashesPerProcess = ((2 ** maxPower) - (2 ** minPower)) // cpuCount
    return [(hashesPerProcess * i, hashesPerProcess * (i + 1)) for i in range(cpuCount)]


if __name__ == '__main__':
    main()
