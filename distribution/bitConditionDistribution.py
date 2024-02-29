import os
import re
import time
from datetime import datetime
import sys
from operator import add


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


def main():
    start = time.perf_counter()
    processIds = []
    collisionsPerProcess = []
    Qs = []
    Q2s = [[], [], [], [], []]
    block1Times = []
    block2Times = [[], [], [], [], [], []]
    try:
        with open(sys.argv[1], "r") as log:
            next(log)
            collisionCount = 0
            for line in log:
                collisionCount += 1
                line = re.sub("\['|'\]\n", '', line)
                splitLine = line.split("', '")
                # Match the type of the second block (Stevens 00, 01, 10, 11, default Wang)
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
                # Make tuples for each process with processIds, number of collisions and average time
                if splitLine[0].split()[0] not in processIds:
                    processIds += [splitLine[0].split()[0]]
                    collisionsPerProcess += [
                        [splitLine[0].split()[0], 1, float(splitLine[len(splitLine) - 1].split(": ")[1])]]
                else:
                    for elem2 in collisionsPerProcess:
                        if elem2[0] == splitLine[0].split()[0]:
                            elem2[1] += 1
                            elem2[2] = float(splitLine[len(splitLine) - 1].split(": ")[1])

                if splitLine[5][3:13] == "0x00000000":
                    Qs += [splitLine[5][15:].split(", ")]
                else:
                    Qs += [splitLine[5][3:].split(", ")]

                if splitLine[6][4:14] == "0x00000000":
                    Q2s[block2Type] += [splitLine[6][16:].split(", ")]
                else:
                    Q2s[block2Type] += [splitLine[6][4:].split(", ")[4:]]

                block1Times += [float(splitLine[7].split(": ")[1])]
                block2Times[block2Type] += [float(splitLine[8].split(": ")[1])]

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
            print(len(Q2))
            print(len(Q2[0]))
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
    distributionFilePath = os.path.join(newDir, f"distribution_{now}.txt")
    bitcondFilePath = os.path.join(newDir, f"bitConditions_{now}.txt")
    with open(distributionFilePath, "w+") as file, open(bitcondFilePath, "w+") as file2:
        for bitDistribution in bitDistributions:
            file.write(f"Block {counter}:\n\n")
            file2.write(f"Block {counter}:\n\n")
            for i, state in enumerate(bitDistribution):
                for j, elem in enumerate(state):
                    file.write(f"{elem}  ")
                    if elem == "1.000000000000000":
                        file2.write(f"1")
                    elif elem == "0.000000000000000":
                        file2.write(f"0")
                    elif i > 0 and elem == bitDistribution[i - 1][j]:
                        file2.write(f"^")
                    elif i > 0 and (float(elem) + float(bitDistribution[i - 1][j])) == 1:
                        file2.write(f"!")
                    else:
                        file2.write(f".")
                    if j % 4 == 3:
                        file.write(f" ")
                        file2.write(f" ")
                file.write(f"\n")
                file2.write(f"\n")
            counter += 1
            file.write(f"\n\n")
            file2.write(f"\n\n")
    file.close()
    print("Done")


if __name__ == '__main__':
    main()
