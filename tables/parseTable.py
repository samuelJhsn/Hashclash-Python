import random
import re
import sys
from pathlib import Path


def main():
    try:
        tableName = Path(sys.argv[1]).stem
        with open(sys.argv[1], "r") as table, open(f"{tableName}_output.py", "w") as output:
            count = 0
            output.write(f"import random\n\n\n"
                         f"def {tableName}Block1():\n"
                         f"\tblock = [0] * 16\n"
                         f"\tQ = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476] + [0] * 64\n")
            output.write(f"\tA, I, J = (random.randint(0, 1),\n"
                         f"\t\t\trandom.randint(0, 1),\n"
                         f"\t\t\trandom.randint(0, 1))\n"
                         f"\tB, K = ~A, ~I\n\n")
            for line in table:
                count += 1
                if re.match(r"(?i)Block 2:", line) is not None:
                    output = open(f"{tableName}_output2.py", "w")
                    output.write(f"import random\n\n\n"
                                 f"def {tableName}Block2(IV):\n"
                                 f"\tblock = [0] * 16\n"
                                 f"\tQ = [IV[0], IV[3], IV[2], IV[1]] + [0] * 64\n")
                    output.write(f"\tA, I, J = (random.randint(0, 1),\n"
                                 f"\t\t\trandom.randint(0, 1),\n"
                                 f"\t\t\trandom.randint(0, 1))\n"
                                 f"\tB, K = ~A, ~I\n\n")
                if re.match(r"([-0-9]*) *(- [-0-9]*)* ([ .01^!ABIJK]*)", line) is not None:
                    line = re.sub(r"([-0-9]*)( -[ 0-9]*)? ([ .01^!ABIJK]*)", getMaskFromPattern, line)
                    output.write(line)

    except IndexError as indErr:
        print(f"{indErr}: Expected second argument")
        sys.exit(1)
    except FileNotFoundError as fileNFErr:
        print(f"{fileNFErr}")
        sys.exit(1)


def getMaskFromPattern(match):
    """

    :param match: regex match to be processed
    :return: bitmask
    """
    matchGroup3 = match.group(3).replace(" ", "")
    bitMask = matchGroup3

    charSet = ".^!ABIJK"
    for char in charSet:
        bitMask = bitMask.replace(char, "1")
    bitMask = hex(int(bitMask, 2))
    indexes = [int(match.group(1), 10)]
    if match.group(2) is not None:
        indexes += list(range(int(match.group(1), 10) + 1, int(re.sub(r"\D", r"", match.group(2)), 10) + 1))
    extras = []
    for index in indexes:
        # Generate random value for Q[index]
        randVal = [f"\tQ[{index}] = random.randint(0, (2 ** 32) - 1)\n"]
        extras += randVal

        # If there are any variables (A, B, I, J, K), assign them
        charList = ["A", "B", "I", "J", "K"]
        chars = [[], [], [], [], []]
        charLines = []
        chars[0] += [i for i, ltr in enumerate(matchGroup3) if ltr == "A"]
        chars[1] += [i for i, ltr in enumerate(matchGroup3) if ltr == "B"]
        chars[2] += [i for i, ltr in enumerate(matchGroup3) if ltr == "I"]
        chars[3] += [i for i, ltr in enumerate(matchGroup3) if ltr == "J"]
        chars[4] += [i for i, ltr in enumerate(matchGroup3) if ltr == "K"]
        print(chars)
        for i, subChars in enumerate(chars):
            if subChars:
                for pos in subChars:
                    charLines += [f"\tQ[{index}] |= {charList[i]} << {31 - pos}\n"]
                print(f"{i}: {subChars}")
        if charLines:
            extras += charLines
        # Set bits at specified position to the same value as Q[index-1]
        posNum = 0
        for i, ltr in enumerate(matchGroup3):
            if ltr == "^":
                posNum += 0x80000000 >> i
        if posNum != 0:
            posSame = f"\tQ[{index}] |= Q[{index - 1}] & {hex(posNum)}\n"
            extras += posSame

        # Set bits at specified position to the opposite value as Q[index-1]
        posNotNum = 0
        for i, ltr in enumerate(matchGroup3):
            if ltr == "!":
                posNotNum += 0x10000000 >> i
        if posNotNum != 0:
            posNotSame = f"\tQ[{index}] ^= Q[{index - 1}] & {hex(posNum)}\n"
            extras += posNotSame

        # Set 0 and 1 bits specified by bitcondition
        bitMaskLine = [f"\tQ[{index}] &= {bitMask}\n"]
        extras += bitMaskLine

    outprint = ""
    for extra in extras:
        for line in extra:
            outprint += line
    return outprint


if __name__ == '__main__':
    main()
