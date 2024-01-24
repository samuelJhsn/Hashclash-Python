import csv
import hashlib
import os
import random
import re
import time
from datetime import datetime
import numpy as np
import sys
from multiprocessing import Pool, cpu_count
import math
from pathlib import Path
from operator import add
import matplotlib.pyplot as plt
import seaborn as sns


def getBitDistribution(states):
    stateCount = len(states)
    bitDistribution = [[0] * 32] * 64
    states = [[list(map(int, list(f'{int(Q, 16):0>32b}'))) for Q in state] for state in states]
    startBitCount = time.perf_counter()

    for state in states:
        for i, Q in enumerate(state):
            bitDistribution[i] = list(map(add, bitDistribution[i], Q))

    bitDistribution = [[f"{round(bitCount / stateCount, 5):.5f}"[:-1] for bitCount in state] for state in bitDistribution]
    endBitCount = time.perf_counter()

    print(f"Took {endBitCount - startBitCount} seconds to count {len(states) * 64 * 32} bits in all states.")

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
    start = time.perf_counter()
    processIds = []
    collisionsPerProcess = []
    Qs = []
    Q2s = []
    avgBlock1Time = []
    avgBlock2Time = []
    avgCollTime = []
    try:
        with open(sys.argv[1], "r") as log:
            next(log)
            collisionCount = 0
            for line in log:
                # print(line)
                collisionCount += 1
                line = re.sub("\['|'\]\n", '', line)
                splitLine = line.split("', '")
                for i, elem in enumerate(splitLine):
                    if elem in ["[", "]\n", ", "]:
                        splitLine.remove(elem)
                    elif i == 0:
                        if elem.split()[0] not in processIds:
                            processIds += [elem.split()[0]]
                            collisionsPerProcess += [[elem.split()[0], 1, float(splitLine[len(splitLine)-1].split(": ")[1])]]
                        else:
                            for elem2 in collisionsPerProcess:
                                if elem2[0] == elem.split()[0]:
                                    elem2[1] += 1
                                    elem2[2] = float(splitLine[len(splitLine)-1].split(": ")[1])
                    elif i == 5:
                        Qs += [elem.split(", ")[1:]]
                    elif i == 6:
                        Q2s += [elem.split(",")[1:]]
                    elif i == 9:
                        avgBlock1Time += [float(elem.split(": ")[1])]
                    elif i == 10:
                        avgBlock2Time += [float(elem.split(": ")[1])]
                    elif i == 11:
                        avgCollTime += [float(elem.split(": ")[1])]

            time.sleep(1)
    except FileNotFoundError as fileNoFoErr:
        print(f"{fileNoFoErr}")
        sys.exit(1)
    # print(processIds)
    collisionsPerProcess.sort()
    print(collisionCount)
    averageCollisionTime = 0
    for process in collisionsPerProcess:
        averageCollisionTime += process[1] * process[2]
    averageCollisionTime /= collisionCount
    # print(averageCollisionTime)
    # print(Qs)
    # print(Q2s)
    # print(avgBlock1Time)
    # print(avgBlock2Time)
    # print(avgCollTime)
    bitDistribution = getBitDistribution(Qs)
    print(bitDistribution)

    filePath = os.path.join(os.getcwd(), f"distribution_{sys.argv[1]}")
    with open(filePath, "w+") as file:
        for state in bitDistribution:
            for elem in state:
                file.write(f"{elem} ")
            file.write(f"\n")
        file.close()
    end = time.perf_counter()
    print(f"Took {end - start} seconds for everything")


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
