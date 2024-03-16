import re
import os


def replaceAdd(match):
    return f"Q[{3 + int(match.group(1))}]"


def replaceSub(match):
    return f"Q[{3 - int(match.group(1))}]"


if __name__ == '__main__':
    for file in os.listdir(os.getcwd()):
        if file.endswith("REPLACEME.EXAMPLE"):
            with open(file, "r+") as f:
                f.seek(0)
                text = f.read()
                text = re.sub(r"std::cout << (\".\") << std::flush", r"print(\1, end=\"\"))", text)

                text = re.sub(r"\)( *)continue", r"):\ncontinue", text)

                text = re.sub(r"FF", r"F", text)
                text = re.sub(r"GG", r"G", text)
                text = re.sub(r"HH", r"H", text)
                text = re.sub(r"II", r"I", text)
                text = re.sub(r"RR", r"crs", text)
                text = re.sub(r"RL", r"cls", text)

                # text = re.sub(r"md5.md5_reverse_step\((\d*),", r"block[\1] = md5.md5_reverse_step(\1, Q,", text)
                # text = re.sub(r"MD5_REVERSE_STEP\((\d*),", r"block[\1] = md5.md5_reverse_step(\1, Q,", text)
                # text = re.sub(r"MD5_STEP\((.{5}), (\w),", r"\2 = md5.md5_step(\1, \2,", text)
                # text = re.sub(r"md5_compress\((.*), (.*)\)", r"\1 = md5.compress(\1, \2)", text)

                text = re.sub(r"rng\(\)", r"random.randrange(0, (2 ** 32) - 1)", text)

                text = re.sub(r"([^Q]) (= )(.*\+)+(.*)", r"\1 \2(\3\4) & 0xFFFFFFFF", text)
                text = re.sub(r"([^Q]) (= )(.*-)+(.*)", r"\1 \2(\3\4) % (1 << 32)", text)

                text = re.sub(r"Q\[68] = IV\[0], IV\[3], IV\[2], IV\[1]", r"block = [0] * 16 \
#Q = [IV[0], IV[3], IV[2], IV[1]] + [0] * 64", text)

                text = re.sub(
                    r"(cls)(\(\w\(Q[\]\[\w]*,"
                    r" Q[\]\[\w]*, Q[\]\[\w]*\) \+ Q[\]\[\w]* \+ x[\]\[\w]* \+"
                    r" 0x\w*)(, *\d*\))", r"\1(\2) & 0xFFFFFFFF\3",
                    text)

                text = re.sub(r"(crs\()(Q[\]\[\w]* *- *Q[\]\[\w]*)", r"\1(\2) % (1 << 32)", text)

                f.seek(0, 0)  # seek to beginning
                f.write(text)
                f.truncate()  # get rid of any trailing characters
