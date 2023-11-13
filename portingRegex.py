import re
import os


def replaceAdd(match):
    return f"Q[{3 + int(match.group(1))}]"


def replaceSub(match):
    return f"Q[{3 - int(match.group(1))}]"


if __name__ == '__main__':
    for file in os.listdir(os.getcwd()):
        if file.endswith("TesteRegex.py"):
            with open(file, "r+") as f:
                f.seek(0)
                text = f.read()
                text = re.sub(r"&&|& &", r"and", text)
                text = re.sub(r"\|\|", r"or", text)
                text = re.sub(r"if *\((.*)\)", r"if \1:", text)
                text = re.sub(r"while *\((.*)\)", r"while \1:", text)
                text = re.sub(r"else if", r"elif", text)
                text = re.sub(r";", r"", text)
                text = re.sub(r"(\{ *)", r"", text)
                text = re.sub(r"(} *)", r"", text)
                text = re.sub(r"true", r"True", text)
                text = re.sub(r"false", r"False", text)
                text = re.sub(r"\(true\)", r"True", text)
                text = re.sub(r"\(false\)", r"False", text)
                text = re.sub(r"void", r"def", text)
                text = re.sub(r"\+\+counter", r"counter += 1", text)


                text = re.sub(r"const", r"", text)
                text = re.sub(r"uint32", r"", text)
                text = re.sub(r"unsigned", r"", text)
                text = re.sub(r"std::cout << (\".\") << std::flush", r"print(\1, end=\"\"))", text)


                text = re.sub(r"Qoff", r"3", text)
                text = re.sub(r"Q\[3\s*\+\s*(\d*)]", replaceAdd, text)
                text = re.sub(r"Q\[3\s*-\s*(\d*)]", replaceSub, text)
                text = re.sub(r"\)( *)continue", r"):\ncontinue", text)

                text = re.sub(r"FF([,(])", r"md5.F\1", text)
                text = re.sub(r"GG", r"md5.G", text)
                text = re.sub(r"HH", r"md5.H", text)
                text = re.sub(r"II", r"md5.I", text)
                text = re.sub(r"RR", r"md5.crs", text)
                text = re.sub(r"RL", r"md5.cls", text)

                text = re.sub(r"md5.md5_reverse_step\((\d*),", r"block[\1] = md5.md5_reverse_step(\1, Q,", text)
                text = re.sub(r"MD5_REVERSE_STEP\((\d*),", r"block[\1] = md5.md5_reverse_step(\1, Q,", text)
                text = re.sub(r"MD5_STEP\((.{5}), (\w),", r"\2 = md5.md5_step(\1, \2,", text)
                text = re.sub(r"md5_compress\((.*), (.*)\)", r"\1 = md5.compress(\1, \2)", text)


                text = re.sub(r"xrng64\(\)", r"random.randrange(0, (2 ** 32))", text)

                text = re.sub(r"([^Q]) (= )(.*\+)+(.*)", r"\1 \2(\3\4) & 0xFFFFFFFF", text)
                text = re.sub(r"([^Q]) (= )(.*-)+(.*)", r"\1 \2(\3\4) % (1 << 32)", text)
                text = re.sub(r"([a-z0-9]*) (-=) (.*)", r"\1 = (\1 - \3) % (1 << 32)", text)

                text = re.sub(r"Q\[68] = IV\[0], IV\[3], IV\[2], IV\[1]", r"block = [0] * 16 \
Q = [IV[0], IV[3], IV[2], IV[1]] + [0] * 64", text)


                f.seek(0, 0)  # seek to beginning
                f.write(text)
                f.truncate()  # get rid of any trailing characters
