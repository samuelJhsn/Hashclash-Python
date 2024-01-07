import re
import os


def replaceAdd(match):
    return f"Q[{3 + int(match.group(1))}]"


def replaceSub(match):
    return f"Q[{3 - int(match.group(1))}]"


if __name__ == '__main__':
    for file in os.listdir(os.getcwd()):
        if file.endswith("md5collision_klima.py"):
            with open(file, "r+") as f:
                f.seek(0)
                text = f.read()
                # text = re.sub(r"std::cout << (\".\") << std::flush", r"print(\1, end=\"\"))", text)

                # text = re.sub(r"\)( *)continue", r"):\ncontinue", text)

                # text = re.sub(r"md5.F\(", r"F(", text)
                # text = re.sub(r"md5.G\(", r"G(", text)
                # text = re.sub(r"md5.H\(", r"H(", text)
                # text = re.sub(r"md5.I\(", r"I(", text)
                # text = re.sub(r"md5.crs\(", r"crs(", text)
                # text = re.sub(r"md5.cls\(", r"cls(", text)


                text = re.sub(
                    r"\(crs\(\(Q\[(\d* *)] *- *Q\[\d* *]*\) % \(1 << 32\), *(\d*) *\) *"
                    r" - +F\(Q\[\d* *]*, +Q\[\d* *]*, +Q\[\d* *]*\) +"
                    r"- +Q\[\d* *]* *- * (0x\w*) *\) % \(1 << 32\)", r"md5_reverse_step(\1, \2, \3)", text)

                text = re.sub(
                    r"\(Q[\]\[\w]* * \+ *cls\(\((\w)\((Q[\]\[\w]*),"
                    r" (Q[\]\[\w]*), (Q[\]\[\w]*)\) \+ (Q[\]\[\w]*) \+ (x[\]\[\w]*) \+"
                    r" (0x\w*)\) & 0xFFFFFFFF, *(\d*)\)\) & 0xFFFFFFFF", r"md5_step(\1, \5, \2, \3, \4, \6, \7, \8)", text)

                text = re.sub(
                    r"\(Q[\]\[\w]* * \+ *cls\((\w)\((Q[\]\[\w]*),"
                    r" (Q[\]\[\w]*), (Q[\]\[\w]*)\) \+ (Q[\]\[\w]*) \+ (x[\]\[\w]*) \+"
                    r" (0x\w*), *(\d*)\)\) & 0xFFFFFFFF", r"md5_step(\1, \5, \2, \3, \4, \6, \7, \8)",
                    text)

                f.seek(0, 0)  # seek to beginning
                f.write(text)
                f.truncate()  # get rid of any trailing characters
