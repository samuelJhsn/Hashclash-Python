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

    bitDistribution = [[f"{round(bitCount / stateCount, 16):.16f}"[:-1] for bitCount in state] for state in
                       bitDistribution]
    endBitCount = time.perf_counter()

    print(f"Took {endBitCount - startBitCount} seconds to count {len(states) * 64 * 32} bits in all states.")

    return bitDistribution

# warnings.filterwarnings("ignore")
# @jit(target_backend='cuda', nopython=False)
def main():
    start = time.perf_counter()
    processIds = []
    collisionsPerProcess = []
    Qs = []
    Q2s = [[], [], [], [], [], []]
    avgBlock1Times = []
    avgBlock2Times = [[], [], [], [], [], []]
    avgCollTime = []
    try:
        with open(sys.argv[1], "r") as log:
            next(log)
            collisionCount = 0
            for line in log:
                collisionCount += 1
                line = re.sub("\['|'\]\n", '', line)
                splitLine = line.split("', '")
                match splitLine[0].split(" @ ")[1]:
                    case "St00":
                        block2Type = 0
                    case "St01":
                        block2Type = 1
                    case "St10":
                        block2Type = 2
                    case "St11":
                        block2Type = 3
                    case _:
                        block2Type = 4
                for i, elem in enumerate(splitLine):
                    if i == 0:
                        if elem.split()[0] not in processIds:
                            processIds += [elem.split()[0]]
                            collisionsPerProcess += [
                                [elem.split()[0], 1, float(splitLine[len(splitLine) - 1].split(": ")[1])]]
                        else:
                            for elem2 in collisionsPerProcess:
                                if elem2[0] == elem.split()[0]:
                                    elem2[1] += 1
                                    elem2[2] = float(splitLine[len(splitLine) - 1].split(": ")[1])
                    elif i == 5:
                        if elem[3:13] == "0x00000000":
                            Qs += [elem[15:].split(", ")]
                        else:
                            Qs += [elem[3:].split(", ")]
                    elif i == 6:
                        if elem[4:14] == "0x00000000":
                            Q2s[block2Type] += [elem[16:].split(", ")[4:]]
                        else:
                            Q2s[block2Type] += [elem[4:].split(", ")[4:]]
                    elif i == 9:
                        avgBlock1Times += [float(elem.split(": ")[1])]
                    elif i == 10:
                        avgBlock2Times[block2Type] += [float(elem.split(": ")[1])]
                    elif i == 11:
                        avgCollTime += [float(elem.split(": ")[1])]

            time.sleep(1)
    except FileNotFoundError as fileNoFoErr:
        print(f"{fileNoFoErr}")
        sys.exit(1)

    collisionsPerProcess.sort()
    averageCollisionTime = 0
    for process in collisionsPerProcess:
        averageCollisionTime += process[1] * process[2]
    averageCollisionTime /= collisionCount
    print(f"Average collision time for all {collisionCount} collisions: {averageCollisionTime}")
    bitDistributionQs = getBitDistribution(Qs)
    bitDistributionQ2s = []
    for Q2 in Q2s:
        if Q2:
            bitDistributionQ2s += [getBitDistribution(Q2)]
    makeTables([bitDistributionQs, *bitDistributionQ2s])

    end = time.perf_counter()
    print(f"Took {end - start} seconds for everything")


def makeTables(bitDistributions):
    now = datetime.now().strftime("%H_%M_%S")
    counter = 0
    newDir = os.getcwd() + "\\bitConditions"
    if not os.path.exists(newDir):
        os.makedirs(newDir)
    os.chdir(newDir)
    for bitDistribution in bitDistributions:
        distributionFilePath = os.path.join(newDir, f"{counter}_distribution_{now}.txt")
        bitcondFilePath = os.path.join(newDir, f"{counter}_bitConditions_{now}.txt")
        with open(distributionFilePath, "w+") as file, open(bitcondFilePath, "w+") as file2:
            counter += 1
            for i, state in enumerate(bitDistribution):
                for j, elem in enumerate(state):
                    file.write(f"{elem}  ")
                    if elem == "1.000000000000000":
                        file2.write(f"1 ")
                    elif elem == "0.000000000000000":
                        file2.write(f"0 ")
                    elif i > 0 and elem == bitDistribution[i - 1][j]:
                        file2.write(f"^ ")
                    elif i > 0 and (float(elem) + float(bitDistribution[i - 1][j])) == 1:
                        file2.write(f"! ")
                    else:
                        file2.write(f". ")
                    if j % 8 == 7:
                        file.write(f"\t")
                        file2.write(f"\t")
                file.write(f"\n")
                file2.write(f"\n")

            file.close()
    print("Done")


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
