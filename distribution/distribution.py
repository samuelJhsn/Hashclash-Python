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
import seaborn as sns


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

    print(f"Took {endBitCount - startBitCount} seconds to count "
         f"{8 * hashlib.md5().digest_size * len(hashes)} bits in all hashes.")

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

    id = datetime.now().strftime("%H_%M_%S_") + f"{os.getpid()}"
    plt.figure(id)
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
        if (i + 2000) % 2000 == 0:
            plt.figure(id + str(i))
            ax = plt.gca()
            ax.set_ylim([-bitsPerHash // 3, bitsPerHash // 3])
            plt.xlabel("bit position")
            plt.ylabel("cumulative bit value")
            plt.plot(xPos, yPos)
            # plt.scatter(zeroPos, [0] * len(zeroPos), marker="o")
            plt.scatter(zeroPos * 2, [ax.get_ylim()[0] // 5] * len(zeroPos) + [ax.get_ylim()[1] // 5] * len(zeroPos),
                        marker="o")
            plt.savefig(id + str(i))
        plt.figure(id)
        plt.plot(xPos, yPos)

    plt.figure(id)
    ax = plt.gca()
    ax.set_ylim([min(-40, min(allMinY) - 5), max(40, max(allMaxY) + 5)])
    plt.savefig(id)

    randomWalkStats = [round((np.mean([elem for elem in allZeroPos if elem != 0])), 1),
                       min(allMinY), max(allMaxY), round((np.mean(endPoints)), 4), allZeroPos, endPoints]

    os.chdir(oldDir)

    return randomWalkStats


# warnings.filterwarnings("ignore")
# @jit(target_backend='cuda', nopython=False)
def main():
    try:
        if sys.argv[1].lower() not in hashlib.algorithms_guaranteed:
            print(f"Try again with a valid hash function out of: {hashlib.algorithms_guaranteed}")
            sys.exit(1)
        hashFunction = getattr(hashlib, sys.argv[1])
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
    plt.rcParams['figure.dpi'] = 300
    with Pool(cpuCount) as p:
        hashingParams = [tup + (hashFunction,) for tup in compRooms]
        print(f"Generating {compRooms[0][1]} {sys.argv[1]} hashes in each of {cpuCount} "
              f"processes (= {compRooms[0][1] * cpuCount} hashes), please "
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

    allZeroPos = [result[4] for result in randWalkStats]
    allZeroPos = sum(allZeroPos, [])
    makeHistogram(allZeroPos, "zeroPos")

    allEndPoints = [result[5] for result in randWalkStats]
    allEndPoints = sum(allEndPoints, [])
    makeHistogram(allEndPoints, "allEndPoints")

    for result in randWalkStats:
        del result[-2:]
    meanZeroPos = round(np.mean([result[0] for result in randWalkStats]))
    minYPos = min([result[1] for result in randWalkStats])
    maxYPos = min([result[2] for result in randWalkStats])
    meanEndPoints = round(np.mean([result[3] for result in randWalkStats]), 3)

    randWalkStats.insert(0, ["Mean of zero positions", "Minimum y value", "Maximum y value", "Mean of end points"])
    randWalkStats.append(["Mean of all zero positions", "Minimum of all y value",
                          "Maximum of all y value", "Mean of all end points"])
    randWalkStats.append([meanZeroPos, minYPos, maxYPos, meanEndPoints])

    with open("randomWalkStats.csv", "w") as f:
        writer = csv.writer(f, delimiter=';', lineterminator='\n')
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


def freedmanDiaconisBinCount(data):
    q25, q75 = np.percentile(data, [25, 75])
    bin_width = 2 * (q75 - q25) * len(data) ** (-1 / 3)
    bins = round((max(data) - min(data) / bin_width))
    return bins


def makeHistogram(data, graphName=""):
    bins = freedmanDiaconisBinCount(data)

    plt.figure(f"sns_{graphName}.png")
    sns.displot(data, bins=bins, kde=True)
    plt.ylabel('Count')
    plt.xlabel('Data')
    plt.savefig(f"sns_{graphName}.png")


if __name__ == '__main__':
    main()
