import re
import sys


def main():
    try:
        with open(sys.argv[1], "r") as table, open(f"{sys.argv[1]}_output.txt", "w") as output:
            count = 0
            for line in table:
                count += 1
                if re.match(r"(?i)Block 2:", line) is not None:
                    output = open(f"{sys.argv[1]}_output2.txt", "w")
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
    chars = ".^!ABIJK"
    for char in chars:
        bitMask = bitMask.replace(char, "1")
    bitMask = hex(int(bitMask, 2))
    indexes = [int(match.group(1), 10)]
    if match.group(2) is not None:
        indexes += list(range(int(match.group(1), 10) + 1, int(re.sub(r"\D", r"", match.group(2)), 10) + 1))
    extras = [[], []]
    for index in indexes:
        posSame = [f"Q[{index}] = Q[{index - 1}] & (0x80000000 >> {i})\n" for
                   i, ltr in
                   enumerate(matchGroup3) if ltr == "^"]
        posNotSame = [f"Q[{index}] = Q[{index - 1}] ^ (0x10000000 >> {i})\n" for
                      i, ltr in
                      enumerate(matchGroup3) if ltr == "!"]
        posNotSame += [f"Q[{index}] &= {bitMask}\n"]
        extras[0] += posSame
        extras[1] += posNotSame

    outprint = ""
    for line in extras[0]:
        outprint += line
    for line in extras[1]:
        outprint += line
    return outprint


if __name__ == '__main__':
    main()
