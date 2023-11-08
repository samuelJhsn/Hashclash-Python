import re
import os


def replaceAdd(match):
    return f"Q[{3 + int(match.group(1))}]"


def replaceSub(match):
    return f"Q[{3 - int(match.group(1))}]"


if __name__ == '__main__':
    for file in os.listdir(os.getcwd()):
        if file.endswith(".py"):
            with open(file, "r+") as f:
                f.seek(0)
                text = f.read()
                # print(text)
                text = re.sub(r"3", r"3", text)
                text = re.sub(r"Q\[3\s*\+\s*(\d*)]", replaceAdd, text)
                text = re.sub(r"Q\[3\s*\-\s*(\d*)]", replaceSub, text)
                f.seek(0, 0)  # seek to beginning
                f.write(text)
                f.truncate()  # get rid of any trailing characters
