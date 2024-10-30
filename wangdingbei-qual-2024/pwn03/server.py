import os, string, random
from signal import alarm

SIZE_MAX = 0x2000

dic = string.ascii_letters + string.digits


def genrandstr(len):
    result = ""
    for _ in range(len):
        result += random.choice(dic)
    return result


def main():
    alarm(40)
    try:
        code = """
        """

        new = ""
        finished = False
        print("Send code with EOF end plz.")
        while SIZE_MAX > len(code):
            new = raw_input("code> ")
            if "EOF" in new:
                finished = True
                break
            code += new + "\n"

        if not finished:
            print("file too large!")
            return

        jsfilename = "/tmp/" + genrandstr(10)

        with open(jsfilename, "w+") as f:
            f.write(code.encode())

        os.system("/home/wdb/pwn " + jsfilename)
        os.system("rm -rf " + jsfilename)

    except:
        print("Error!")


if __name__ == "__main__":
    main()

