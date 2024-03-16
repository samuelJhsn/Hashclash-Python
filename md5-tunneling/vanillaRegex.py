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
                text = re.sub(
                    r"cls\(\((\w\(Q[\]\[\w]*,"
                    r" Q[\]\[\w]*, Q[\]\[\w]*\) \+ Q[\]\[\w]* \+ x[\]\[\w]* \+"
                    r" 0x\w*)\) & 0xFFFFFFFF, *(\d)*\)",
                    r"((((\1) << \2) & 0xFFFFFFFF) | (((\1) & 0xFFFFFFFF) >> (32 - \2)))",
                    text)

                text = re.sub(r"crs\((\(Q[\]\[\w]* *- *Q[\]\[\w]*\) % \(1 << 32\)), *(\d)*\)",
                             r"(((\1) >> \2) | (((\1)) << (32 - \2)))", text)

                text = re.sub(r"F\((Q[\]\[\w]*), (Q[\]\[\w]*), (Q[\]\[\w]*)\)", r"(\3 ^ (\1 & (\2 ^ \3)))", text)
                text = re.sub(r"G\((Q[\]\[\w]*), (Q[\]\[\w]*), (Q[\]\[\w]*)\)", r"(\2 ^ (\3 & (\1 ^ \2)))", text)
                text = re.sub(r"H\((Q[\]\[\w]*), (Q[\]\[\w]*), (Q[\]\[\w]*)\)", r"(\1 ^ \2 ^ \3)", text)
                text = re.sub(r"I\((Q[\]\[\w]*), (Q[\]\[\w]*), (Q[\]\[\w]*)\)", r"(\2 ^ (\1 | ~\3))", text)

                f.seek(0, 0)  # seek to beginning
                f.write(text)
                f.truncate()  # get rid of any trailing characters
