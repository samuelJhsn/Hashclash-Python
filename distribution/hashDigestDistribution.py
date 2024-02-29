import csv
import hashlib
import os
import random
import time
from collections import Counter
from datetime import datetime
import numpy as np
import sys
from multiprocessing import Pool, cpu_count
import math
from operator import add
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

def getHashes(compRoomStart, compRoomEnd, hashFunction):
    randomBitString = True
    bitStrings = []
    if randomBitString:
        for _ in range(compRoomStart, compRoomEnd):
            randomNumba = random.randint(0, 2 ** 512)
            bitStrings.append(randomNumba.to_bytes(math.ceil(randomNumba.bit_length() / 8), byteorder='big'))
    else:
        bitStrings = [e.to_bytes(math.ceil(e.bit_length() / 8), byteorder='big')
                      for e in range(compRoomStart, compRoomEnd)]

    hashes = [hashFunction(bitString).hexdigest() for bitString in bitStrings]
    hashes = [list(f'{int(h, 16):0>{8 * hashFunction().digest_size}b}') for h in hashes]
    hashes = [[int(numba) for numba in h] for h in hashes]

    bitStrings = [bitString.hex() for bitString in bitStrings]
    bitStrings = [list(f'{int(bitString, 16):0>512b}') for bitString in bitStrings]
    bitStrings = [[int(numba) for numba in bitString] for bitString in bitStrings]

    return hashes, bitStrings


def calcBitDistribution(bitStrings):
    bitDistribution = [0] * 512

    for bitString in bitStrings:
        bitDistribution = list(map(add, bitDistribution, bitString))

    return bitDistribution


def getHashBitDistribution(hashes, hashFunction):
    bitDistribution = [0] * (8 * hashFunction().digest_size)

    for h in hashes:
        bitDistribution = list(map(add, bitDistribution, h))

    return bitDistribution


def getRandomWalkStats(hashes, hashFunction):
    print(f"Starting random walk calculations...")
    bitsPerHash = 8 * hashFunction().digest_size
    hashesRandWalk = [[h, bitsPerHash / 2 - sum(h)]
                      for h in hashes]  # Map each hash to pair (itself, hashlength - N of 1-bits)
    oldDir = os.getcwd()
    newDir = os.path.join(os.getcwd(), "randomWalks")
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
        if y == 0:
            zeroPos += [xPos[128]]
        endPoints += [y]
        allMaxY += [maxY]
        allMinY += [minY]
        allZeroPos += zeroPos
        if (i + 1) % 50000 == 0:
            print(f"Processed 50000 hashes for random walks...")
            plt.figure(id + str(i))
            ax = plt.gca()
            ax.set_ylim([-bitsPerHash // 3, bitsPerHash // 3])
            plt.xlabel("bit position")
            plt.ylabel("cumulative bit value")
            plt.plot(xPos, yPos)
            # plt.scatter(zeroPos, [0] * len(zeroPos), marker="o")
            # plt.scatter(zeroPos * 2, [ax.get_ylim()[0] // 5] * len(zeroPos) + [ax.get_ylim()[1] // 5] * len(zeroPos), marker="o")
            plt.savefig(id + "_" + str(i))
        plt.figure(id)
        plt.plot(xPos, yPos)

    plt.figure(id)
    ax = plt.gca()

    # Set y-axis limit symetrically to either extreme value or else 40
    yLimit = max(40, -min(allMinY) + 5, max(allMaxY) + 5)
    ax.set_ylim(-yLimit, yLimit)
    # Set the ticks for x- and y-axis
    xticks = list(range(0, bitsPerHash + 1, 8))
    yticks = list(range(0, -yLimit, -5)) + list(range(0, yLimit, 5))[1:]
    plt.xticks(xticks)
    plt.yticks(yticks)

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
        cpuCount = int(cpu_count() * 0.9)
        compRooms = getCompRooms(0, int(sys.argv[2]), cpuCount)
    except ValueError as valErr:
        print(f"{valErr}: Expected int, found {type(sys.argv[2])}")
        sys.exit(1)
    except IndexError as indErr:
        print(f"{indErr}: Expected second argument")
        sys.exit(1)

    start = time.perf_counter()
    plt.rcParams['figure.dpi'] = 2000
    with Pool(cpuCount) as p:
        hashingParams = [tup + (hashFunction,) for tup in compRooms]
        print(f"Generating {compRooms[0][1]} {sys.argv[1]} hashes in each of {cpuCount} "
              f"processes (= {compRooms[0][1] * cpuCount} hashes), please "
              f"wait...")
        hashes = p.starmap(getHashes, hashingParams)
        bitStrings = [pair[1] for pair in hashes]
        hashes = [pair[0] for pair in hashes]

        statParams = [(partOfHashes, hashFunction,) for partOfHashes in hashes]

        distribution = p.starmap(getHashBitDistribution, statParams)
        bitStringBitDistribution = p.map(calcBitDistribution, bitStrings)

        randWalkStats = p.starmap(getRandomWalkStats, statParams)

    print("Saving distributions and random walks...")
    distribution = [sum(x) for x in zip(*distribution)]
    bitStringBitDistribution = [sum(x) for x in zip(*bitStringBitDistribution)]

    np.savetxt("hashDigestBitdistribution.csv",
               distribution,
               delimiter=", ",
               fmt="% s")
    np.savetxt("bitStringBitDistribution.csv",
               bitStringBitDistribution,
               delimiter=", ",
               fmt="% s")

    allZeroPos = [result[4] for result in randWalkStats]
    allZeroPos = sum(allZeroPos, [])
    makeBarplot(allZeroPos, "zeroPos")

    allEndPoints = [result[5] for result in randWalkStats]
    allEndPoints = sum(allEndPoints, [])
    makeBarplot(allEndPoints, "allEndPoints")

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
    print(f"Took {end - start} seconds to process {compRooms[0][1] * cpuCount} values in {cpuCount} processes")


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
    hashesPerProcess = (((2 ** maxPower) - (2 ** minPower)) // cpuCount) + 1
    return [(hashesPerProcess * i, hashesPerProcess * (i + 1)) for i in range(cpuCount)]


def makeBarplot(data, graphName=""):
    data = pd.DataFrame.from_dict(Counter(data), orient="index").reset_index().rename(columns={0: 'count'})
    for scaleType in ["linear", "log"]:
        plt.figure(f"{scaleType}_{graphName}.png")
        ax = sns.barplot(x="index", y="count", data=data)
        ax.set_yscale(scaleType)
        plt.xticks(fontsize=5, rotation=90)
        ax.bar_label(ax.containers[0], padding=1, fontsize=5, rotation=90, fmt="%d")
        sns.despine(top=True, right=True)

        plt.xlabel('Coordinate')
        plt.ylabel('Count')
        plt.savefig(f"{scaleType}_{graphName}.png")


if __name__ == '__main__':
    main()
