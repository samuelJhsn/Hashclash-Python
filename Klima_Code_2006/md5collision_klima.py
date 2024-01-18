"""
This program demonstrates the method of tunneling according to

Vlastimil Klima: Tunnels in Hash Functions: MD5 Collisions Within a Minute, 
sent to IACR eprint, 18 March, 2006,
http:#cryptography.hyperlink.cz/2006/tunnels.pdf

Homepage of the project
http:#cryptography.hyperlink.cz/MD5_collisions.html

References [Ri92  ] Ronald Rivest: The MD5 Message Digest Algorithm, RFC1321, April 1992,
ftp:#ftp.rfc-editor.org/in-notes/rfc1321.txt [WFLY04] Xiaoyun Wang, Dengguo Feng , Xuejia Lai, Hongbo Yu: Collisions
for Hash Functions MD4, MD5, HAVAL-128 and RIPEMD, rump session, CRYPTO 2004, Cryptology ePrint Archive,
Report 2004/199, first version (August 16, 2004), second version (August 17, 2004),
http:#eprint.iacr.org/2004/199.pdf [HPR04 ] Philip Hawkes, Michael Paddon, Gregory G. Rose: Musings on the Wang et
al. MD5 Collision, Cryptology ePrint Archive, Report 2004/264, 13 October 2004, http:#eprint.iacr.org/2004/264.pdf [
Kli05a] Vlastimil Klima: Finding MD5 Collisions - a Toy For a Notebook, Cryptology ePrint Archive, Report 2005/075,
http:#eprint.iacr.org/2005/075.pdf, March 5, 2005 [Kli05b] Vlastimil Klima: Finding MD5 Collisions on a Notebook PC
Using Multi-message Modifications, Cryptology ePrint Archive, 5 April 2005. http:#eprint.iacr.org/2005/102.pdf [
WaYu05] X. Wang and H. Yu: How to Break MD5 and Other Hash Functions., Eurocrypt'05, Springer-Verlag, LNCS,
Vol. 3494, pp. 19-35. Springer, 2005. [YaSh05] Jun Yajima and Takeshi Shimoyama: Wang's sufficient conditions of MD5
are not sufficient, Cryptology ePrint Archive: Report 2005/263, 10 Aug 2005, http:#eprint.iacr.org/2005/263.pdf [
SNKO05] Yu Sasaki and Yusuke Naito and Noboru Kunihiro and Kazuo Ohta: Improved Collision Attack on MD5, Cryptology
ePrint Archive: Report 2005/400, 7 Nov 2005, http:#eprint.iacr.org/2005/400.pdf [LiLa05] Liang J. and Lai X.:
Improved Collision Attack on Hash Function MD5, Cryptology ePrint Archive: Report 425/2005, 23 Nov 2005,
http:#eprint.iacr.org/2005/425.pdf.

I wrote this program for educational purposes. 
It demonstrates my method of tunneling in both blocks of the message. 
The program is provided as is.
No guarantee is given on how it may function or malfunction. 
It is forbidden to use it for commercial or malicious use.
Further distribution is not allowed without my permission.

Copyright: Vlastimil Klima, http:#cryptography.hyperlink.cz

Note: I am very sorry, the program is very bad. I am not a programmer.
On the other hand, there is a possibility to improve it and to speed up the collision search.

    Version: 1.

        Changes from version 0:
        I tried to optimize the block 1.
        I added two new tunnels and new multi-message modification methods (MMMM) into the block 2.

        (one MMMM is prepared in extra conditions, not programmed:
        on bits where (Q11=Q12 and Q9=Q10) it is possible to change both the bits Q11(Q12)
        without disturbing x11, Q[17..21])

        On a slow notebook (Pentium, 1.6 GHz) it takes roughly
        31 seconds per collision in average	  (block 1: 30 seconds ,  block 2: 1 second).

        Note: For debugging I used the parameter
        md5tunnel.exe 47777A2B
        it gives collisions very quickly...

"""
import os
import sys
import time

import md5
import random
from datetime import datetime
from multiprocessing import cpu_count, Pool

MD5_IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

Q2 = [0] * 65
hashDigest = [0] * 4
collision_count = 0  # ulong
out_filename = [""] * 64  # char
P_IHV1, P_HIHV1 = [0] * 4, [0] * 4  # ulong
buffer = [""] * 2048  # char
time3 = time4 = time5 = 0  # double
now = datetime.now().strftime("%d%m%Y-%H%M%S")

x1, M1, x2, M2 = [""] * 16, [""] * 16, [""] * 16, [""] * 16  # unsigned char

longmask = [0] * 32  # unsigned long
longmask = [0] + [(1 << k) for k in range(len(longmask))]


def cls(a, rc):
    return ((a << rc) & 0xFFFFFFFF) | (a >> (32 - rc))


def crs(a, rc):
    return (a >> rc) | ((a << (32 - rc)) & 0xFFFFFFFF)


def F(b, c, d): return d ^ (b & (c ^ d))


def G(b, c, d): return c ^ (d & (b ^ c))


def H(b, c, d): return b ^ c ^ d


def I(b, c, d): return c ^ (b | ~d)


mask2Q9 = [0] * 256
mask2Q9 = [(0x100000 * (k // 32) + 0x400 * (k // 8 % 2) + 4 * (k % 8) + 0x40000 * (k // 16 % 2)) for k in
           range(len(mask2Q9))]

mask_Q9 = [0] * 8
mask_Q9 = [(0x200000 * k) for k in range(len(mask_Q9))]

maskQ10 = [0x0, 0x400, 0x1000000, 0x1000400, 0x4000000, 0x4000400, 0x5000000, 0x5000400]

maskQ14 = [0] * 512
maskQ14 = [(k % 8 + (0x10 * (k // 8 % 8)) + 0x4000000 * (k // 64)) for k in range(len(maskQ14))]

maskQ20 = [0] * 64
maskQ20 = [(k % 4 + 0x200 * (k // 4 % 2) +
            0x4000 * (k // 8 % 2) + 0x200000 * (k // 16 % 2) + 0x800000 * (k // 32)) for k in range(len(maskQ20))]

maskQ13 = [0] * 4096
maskQ13 = [(0x2 * (k % 4) + 0x10 * (k // 4 % 2) + 0x40 * (k // 8 % 2) +
            0x200 * (k // 16 % 8) + 0x100000 * (k // 128 % 8) +
            0x8000000 * (k // 1024)) for k in range(len(maskQ13))]


def findBlock1():
    filePath = os.path.join(os.getcwd(), "collisions", f"state_{now}.txt")
    with open(filePath, "a+") as file:
        file.write(f"{os.getpid()} @ {datetime.now().strftime('%d.%m.%Y-%H:%M:%S')}: state is {random.getstate()}\n\n")
        file.close()

    Q = [0] * 65
    x = [0] * 16
    IHV1, IHV0, HIHV1, HIHV0 = [0] * 4, [0] * 4, [0] * 4, [0] * 4  # ulong

    QM3 = IHV0[0] = MD5_IV[0]
    QM0 = IHV0[1] = MD5_IV[1]
    QM1 = IHV0[2] = MD5_IV[2]
    QM2 = IHV0[3] = MD5_IV[3]

    startTime = time.perf_counter()

    Q[7] = 0x03fef820

    while True:
        # a1 
        Q[1] = random.randint(0, (2 ** 32) - 1)
        # d1 
        # Q[ 2] = (random.randint(0, (2 ** 32) - 1)) % (1 << 32)
        # c1 
        # Q[3]          = .... .... .vvv 0vvv vvvv 0vvv v0.. ....
        # position with RNG  = **** **** **** .*** **** .*** *.** ****  0xfff7f7bf
        # position with 0    = .... .... .... *... .... *... .*.. ....  0x00080840
        # position with 1    = .... .... .... .... .... .... .... ....  0x00000000
        Q[3] = random.randint(0, (2 ** 32) - 1) & 0xfff7f7bf

        # b1 
        # Q[ 4]         = 1... .... 0^^^ 1^^^ ^^^^ 1^^^ ^011 ....
        # position with RNG  = .*** **** .... .... .... .... .... ****  0x7f00000f
        # position with 0    = .... .... *... .... .... .... .*.. ....  0x00800040
        # position with 1    = *... .... .... *... .... *... ..** ....  0x80080830
        # position with Q[3] = .... .... .*** .*** **** .*** *... ....  0x0077f780
        Q[4] = ((random.randint(0, (2 ** 32) - 1) & 0x7f00000f) + 0x80080830 + (Q[3] & 0x0077f780))

        # a2 - I set bit 2 and 4 to zero, not necessary for Q14 tunnel 
        # Q[ 5]         = 1000 100v 0100 0000 0000 0000 0010 0101
        # position with RNG  = .... ...* .... .... .... .... .... ....  0x01000000
        # position with 0    = .*** .**. *.** **** **** **** **.* *.*.  0x76bfffda
        # position with 1    = *... *... .*.. .... .... .... ..*. .*.*  0x88400025
        Q[5] = (random.randint(0, (2 ** 32) - 1) & 0x01000000) + 0x88400025

        # d2 - I set bit 2 and 4 to zero, not necessary for Q14 tunnel
        # Q[ 6]         = 0000 001^ 0111 1111 1011 1100 0100 0001
        # position with RNG  = .... .... .... .... .... .... .... ....  0x00000000
        # position with 0    = **** **.. *... .... .*.. ..** *.** ***.  0xfc8043be
        # position with 1    = .... ..*. .*** **** *.** **.. .*.. ...*  0x027fbc41
        # position with Q[ 5]= .... ...* .... .... .... .... .... ....  0x01000000
        Q[6] = 0x027fbc41 + (Q[5] & 0x01000000)

        # c2 
        # Q[ 7]         = 0000 0011 1111 1110 1111 1000 0010 0000
        # position   RNG  = .... .... .... .... .... .... .... ....  0x00000000
        # position   NUL  = **** **.. .... ...* .... .*** **.* ****  0xfc0107df
        # position   ONE  = .... ..** **** ***. **** *... ..*. ....  0x03fef820
        # Q[7] = 0x03fef820

        # b2 
        # Q[ 8]         = 0000 0001 1..1 0001 0.0v 0101 0100 0000
        # position   RNG  = .... .... .**. .... .*.* .... .... ....  0x00605000
        # position   NUL  = **** ***. .... ***. *.*. *.*. *.** ****  0xfe0eaabf
        # position   ONE  = .... ...* *..* ...* .... .*.* .*.. ....  0x01910540
        Q[8] = (random.randint(0, (2 ** 32) - 1) & 0x00605000) + 0x01910540

        # a3 
        # Q[ 9]         = 1111 1011 ...1 0000 0.1^ 1111 0011 1101
        # position   RNG  = .... .... ***. .... .*.. .... .... ....  0x00e04000
        # position   NUL  = .... .*.. .... **** *... .... **.. ..*.  0x040f80c2
        # position   ONE  = **** *.** ...* .... ..*. **** ..** **.*  0xfb102f3d
        # position = Q[ 8]= .... .... .... .... ...* .... .... ....  0x00001000
        Q[9] = (random.randint(0, (2 ** 32) - 1) & 0x00e04000) + 0xfb102f3d + (Q[8] & 0x00001000)

        #  d3 ------ Q9 tunnel , bits 24,23,22
        # Q[10]         = 0111 .... 0001 1111 1v01 ...0 01.. ..00
        # position   RNG  = .... **** .... .... .*.. ***. ..** **..  0x0f004e3c
        # position   NUL  = *... .... ***. .... ..*. ...* *... ..**  0x80e02183
        # position   ONE  = .*** .... ...* **** *..* .... .*.. ....  0x701f9040
        Q[10] = (random.randint(0, (2 ** 32) - 1) & 0x0f004e3c) + 0x701f9040

        #  c3  ------ Q9 tunnel , bits 24,23,22
        # ------------ Q10 tunnel , bits 11,25,27
        # Q[11]         = 0010 .0v0 111. 0001 1^00 .0.0 11.. ..10
        # position   RNG  = .... *.*. ...* .... .... *.*. ..** **..  0x0a100a3c
        # position   NUL  = **.* .*.* .... ***. ..** .*.* .... ...*  0xd50e3501
        # position   ONE  = ..*. .... ***. ...* *... .... **.. ..*.  0x20e180c2
        # position = Q[10]= .... .... .... .... .*.. .... .... ....  0x00004000
        Q[11] = (random.randint(0, (2 ** 32) - 1) & 0x0a100a3c) + 0x20e180c2 + (Q[10] & 0x00004000)

        #  b3
        # Q[12]         = 000. ..^^ .... 1000 0001 ...1 0... ....
        # position   RNG  = ...* **.. **** .... .... ***. .*** ****  0x1cf00e7f
        # position   NUL  = ***. .... .... .*** ***. .... *... ....  0xe007e080
        # position   ONE  = .... .... .... *... ...* ...* .... ....  0x00081100
        # position = Q[11]= .... ..** .... .... .... .... .... ....  0x03000000
        Q[12] = (random.randint(0, (2 ** 32) - 1) & 0x1cf00e7f) + 0x00081100 + (Q[11] & 0x03000000)

        # a4 
        # Q[13]         = 01.. ..01 .... 1111 111. ...0 0... 1...
        # position   RNG  = ..** **.. **** .... ...* ***. .*** .***  0x3cf01e77
        # position   NUL  = *... ..*. .... .... .... ...* *... ....  0x82000180
        # position   ONE  = .*.. ...* .... **** ***. .... .... *...  0x410fe008
        Q[13] = (random.randint(0, (2 ** 32) - 1) & 0x3cf01e77) + 0x410fe008

        # d4 
        # Q[14]         = 000. ..00 .... 1011 111. ...1 1... 1...
        # position   RNG  = ...* **.. **** .... ...* ***. .*** .***  0x1cf01e77
        # position   NUL  = ***. ..** .... .*.. .... .... .... ....  0xe3040000
        # position   ONE  = .... .... .... *.** ***. ...* *... *...  0x000be188
        Q[14] = (random.randint(0, (2 ** 32) - 1) & 0x1cf01e77) + 0x000be188

        # c4 --- Q3x6 tunnel , bits 29,28,27,7,6,5,3,2,1
        # Q[15]         = v110 0001 ..V. .... 10.. .... .000 0000
        # position   RNG  = *... .... **** **** ..** **** *... ....  0x80ff3f80
        # position   NUL  = ...* ***. .... .... .*.. .... .*** ****  0x1e00407f
        # position   ONE  = .**. ...* .... .... *... .... .... ....  0x61008000
        Q[15] = (random.randint(0, (2 ** 32) - 1) & 0x80ff3f80) + 0x61008000
        bit_Q15_32 = Q[15] & longmask[32]

        # b4 --- Q3x6 tunnel , bits 29,28,27,7,6,5,3,2,1
        # Q[16]         = ^010 00.. ..A. .... v... .... .000 v000
        # position   RNG  = .... ..** **.* **** **** **** *... *...  0x03dfff88
        # position   NUL  = .*.* **.. .... .... .... .... .*** .***  0x5c000077
        # position   ONE  = ..*. .... .... .... .... .... .... ....  0x20000000
        # position   Q[15]= *... .... .... .... .... .... .... ....  0x80000000
        # position ~ Q[15]= .... .... ..*. .... .... .... .... ....  0x00200000
        # Q[16] = (random.randint(0, (2 ** 32) - 1) & 0x03dfff88)
        # + 0x20000000 + (Q[15] & 0x80000000) + ((~Q[15]) & 0x00200000)

        Q[16] = (random.randint(0, (2 ** 32) - 1) & 0x03dfff88) + 0x20000000 + (Q[15] & 0x80000000) + (
                    (~Q[15]) & 0x00200000)
        # Q[17]         = ^1v. .... .... ..0. ^... .... .... ^...
        # position   RNG  = ..** **** **** **.* .*** **** **** .***  0x3ffd7ff7
        # position   NUL  = .... .... .... ..*. .... .... .... ....  0x00020000
        # position   ONE  = .*.. .... .... .... .... .... .... ....  0x40000000
        # position   Q[16]= *... .... .... .... *... .... .... *...  0x80008008
        Q[17] = (random.randint(0, (2 ** 32) - 1) & 0x3ffd7ff7) + 0x40000000 + (Q[16] & 0x80008008)

        x[1] = (crs((Q[17] - Q[16]) % (1 << 32), 5) - (Q[15] ^ (Q[14] & (Q[16] ^ Q[15]))) - Q[13] - 0xf61e2562) % (1 << 32)
        Q[2] = (Q[1] + cls(((QM1 ^ (Q[1] & (QM0 ^ QM1))) + QM2 + x[1] + 0xe8c7b756) & 0xFFFFFFFF, 12)) & 0xFFFFFFFF

        x[6] = (crs((Q[7] - Q[6]) % (1 << 32), 17) - (Q[4] ^ (Q[6] & (Q[5] ^ Q[4]))) - Q[3] - 0xa8304613) % (1 << 32)
        x[11] = (crs((Q[12] - Q[11]) % (1 << 32), 22) - (Q[9] ^ (Q[11] & (Q[10] ^ Q[9]))) - Q[8] - 0x895cd7be) % (1 << 32)
        x[0] = (crs((Q[1] - QM0) % (1 << 32), 7) - (QM2 ^ (QM0 & (QM1 ^ QM2))) - QM3 - 0xd76aa478) % (1 << 32)
        x[5] = (crs((Q[6] - Q[5]) % (1 << 32), 12) - (Q[3] ^ (Q[5] & (Q[4] ^ Q[3]))) - Q[2] - 0x4787c62a) % (1 << 32)
        x[10] = (crs((Q[11] - Q[10]) % (1 << 32), 17) - (Q[8] ^ (Q[10] & (Q[9] ^ Q[8]))) - Q[7] - 0xffff5bb1) % (1 << 32)
        x[15] = (crs((Q[16] - Q[15]) % (1 << 32), 22) - (Q[13] ^ (Q[15] & (Q[14] ^ Q[13]))) - Q[12] - 0x49b40821) % (1 << 32)
        x[4] = (crs((Q[5] - Q[4]) % (1 << 32), 7) - (Q[2] ^ (Q[4] & (Q[3] ^ Q[2]))) - Q[1] - 0xf57c0faf) % (1 << 32)

        Q[18] = (Q[17] + cls(((Q[16] ^ (Q[15] & (Q[17] ^ Q[16]))) + Q[14] + x[6] + 0xc040b340) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF

        if ((Q[18] ^ Q[17]) & 0xa0020000) != 0x00020000:
            continue

        zavorka_Q19 = ((Q[17] ^ (Q[16] & (Q[18] ^ Q[17]))) + Q[15] + x[11] + 0x265e5a51) & 0xFFFFFFFF
        if (zavorka_Q19 & 0x0003fff8) == 0x0003fff8:
            continue

        Q[19] = (Q[18] + cls(zavorka_Q19, 14)) & 0xFFFFFFFF
        if ((Q[19] ^ Q[18]) & 0x80020000) != 0x00020000:
            continue

        zavorka_Q20 = ((Q[18] ^ (Q[17] & (Q[19] ^ Q[18]))) + Q[16] + x[0] + 0xe9b6c7aa) & 0xFFFFFFFF
        if (zavorka_Q20 & 0xe0000000) == 0:
            continue

        Q[20] = (Q[19] + cls(zavorka_Q20, 20)) & 0xFFFFFFFF
        if (Q[20] & longmask[32]) != bit_Q15_32:
            continue

        Q[21] = (Q[20] + cls(((Q[19] ^ (Q[18] & (Q[20] ^ Q[19]))) + Q[17] + x[5] + 0xd62f105d) & 0xFFFFFFFF, 5)) & 0xFFFFFFFF
        if ((Q[21] ^ Q[20]) & 0x80020000) != 0:
            continue

        Q[22] = (Q[21] + cls(((Q[20] ^ (Q[19] & (Q[21] ^ Q[20]))) + Q[18] + x[10] + 0x2441453) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
        if (Q[22] & longmask[32]) != bit_Q15_32:
            continue

        zavorka_Q23 = ((Q[21] ^ (Q[20] & (Q[22] ^ Q[21]))) + Q[19] + x[15] + 0xd8a1e681) & 0xFFFFFFFF
        if (zavorka_Q23 & longmask[18]) != 0:
            continue

        Q[23] = ((Q[22] + cls(zavorka_Q23, 14)) & 0xFFFFFFFF) & 0xFFFFFFFF
        if (Q[23] & longmask[32]) != 0:
            continue

        Q[24] = (Q[23] + cls(((Q[22] ^ (Q[21] & (Q[23] ^ Q[22]))) + Q[20] + x[4] + 0xe7d3fbc8) & 0xFFFFFFFF, 20)) & 0xFFFFFFFF
        if (Q[24] & longmask[32]) != longmask[32]:
            continue

        # stat[14]++if(stat[14]==0)Histat[14]++

        # tututu B0
        tempx4 = x[4]
        tempx15 = x[15]
        tempx1 = x[1]
        tempq3 = Q[3]
        tempq4 = Q[4]
        tempq14 = Q[14]
        tempq10 = Q[10]
        tempq9 = Q[9]
        tempq13 = Q[13]
        tempq20 = Q[20]
        tempq21 = Q[21]

        B0a = ((Q[6] ^ (Q[8] & (Q[7] ^ Q[6]))) + Q[5] + 0x698098d8) & 0xFFFFFFFF
        B0b = (Q[6] + 0x8b44f7af) & 0xFFFFFFFF

        for Q10 in range(8):  # 3 bits, 8
            Q[10] = tempq10
            Q[9] = tempq9
            Q[13] = tempq13
            x[4] = tempx4
            x[15] = tempx15
            Q[20] = tempq20
            Q[21] = tempq21

            Q[10] = tempq10 ^ maskQ10[Q10]
            x[10] = (crs((Q[11] - Q[10]) % (1 << 32), 17) - (Q[8] ^ (Q[10] & (Q[9] ^ Q[8]))) - Q[7] - 0xffff5bb1) % (1 << 32)
            Q[22] = (Q[21] + cls(((Q[20] ^ (Q[19] & (Q[21] ^ Q[20]))) + Q[18] + x[10] + 0x2441453) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
            if (Q[22] & longmask[32]) != bit_Q15_32:
                continue
            zavorka_Q23 = ((Q[21] ^ (Q[20] & (Q[22] ^ Q[21]))) + Q[19] + x[15] + 0xd8a1e681) & 0xFFFFFFFF
            if (zavorka_Q23 & longmask[18]) != 0:
                continue
            Q[23] = (Q[22] + cls(zavorka_Q23, 14)) & 0xFFFFFFFF
            if (Q[23] & longmask[32]) != 0:
                continue
            Q[24] = (Q[23] + cls(((Q[22] ^ (Q[21] & (Q[23] ^ Q[22]))) + Q[20] + x[4] + 0xe7d3fbc8) & 0xFFFFFFFF, 20)) & 0xFFFFFFFF
            if (Q[24] & longmask[32]) != longmask[32]:
                continue

            B01a = (x[10] + 0xbebfbc70) & 0xFFFFFFFF

            for Q20 in range(64):  # 6 bits, 64
                Q[3] = tempq3
                Q[4] = tempq4
                x[1] = tempx1
                x[15] = tempx15
                Q[20] = tempq20 ^ maskQ20[Q20]
                x[0] = (crs((Q[20] - Q[19]) % (1 << 32), 20) - (Q[18] ^ (Q[17] & (Q[19] ^ Q[18]))) - Q[16] - 0xe9b6c7aa) % (1 << 32)
                Q[1] = (QM0 + cls(((QM2 ^ (QM0 & (QM1 ^ QM2))) + QM3 + x[0] + 0xd76aa478) & 0xFFFFFFFF, 7)) & 0xFFFFFFFF
                Q[2] = (Q[1] + cls(((QM1 ^ (Q[1] & (QM0 ^ QM1))) + QM2 + x[1] + 0xe8c7b756) & 0xFFFFFFFF, 12)) & 0xFFFFFFFF
                x[5] = (crs((Q[6] - Q[5]) % (1 << 32), 12) - (Q[3] ^ (Q[5] & (Q[4] ^ Q[3]))) - Q[2] - 0x4787c62a) % (1 << 32)
                Q[21] = (Q[20] + cls(((Q[19] ^ (Q[18] & (Q[20] ^ Q[19]))) + Q[17] + x[5] + 0xd62f105d) & 0xFFFFFFFF,
                                     5)) & 0xFFFFFFFF  # was missing
                if ((Q[21] ^ Q[20]) & 0x80020000) != 0:
                    continue
                Q[22] = (Q[21] + cls(((Q[20] ^ (Q[19] & (Q[21] ^ Q[20]))) + Q[18] + x[10] + 0x2441453) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
                if (Q[22] & longmask[32]) != bit_Q15_32:
                    continue
                zavorka_Q23 = ((Q[21] ^ (Q[20] & (Q[22] ^ Q[21]))) + Q[19] + x[15] + 0xd8a1e681) & 0xFFFFFFFF
                if (zavorka_Q23 & longmask[18]) != 0:
                    continue
                Q[23] = (Q[22] + cls(zavorka_Q23, 14)) & 0xFFFFFFFF
                if (Q[23] & longmask[32]) != 0:
                    continue
                x[4] = (crs((Q[5] - Q[4]) % (1 << 32), 7) - (Q[2] ^ (Q[4] & (Q[3] ^ Q[2]))) - Q[1] - 0xf57c0faf) % (1 << 32)
                Q[24] = (Q[23] + cls(((Q[22] ^ (Q[21] & (Q[23] ^ Q[22]))) + Q[20] + x[4] + 0xe7d3fbc8) & 0xFFFFFFFF,
                                     20)) & 0xFFFFFFFF
                if (Q[24] & longmask[32]) != longmask[32]:
                    continue

                B02a = (x[0] + 0xeaa127fa) & 0xFFFFFFFF
                B02b = (x[0] + 0xf4292244) & 0xFFFFFFFF

                for Q13 in range(4096):  # 12 bits
                    Q[3] = tempq3
                    Q[4] = tempq4
                    Q[14] = tempq14
                    Q[13] = tempq13 ^ maskQ13[Q13]
                    x[1] = (crs((Q[17] - Q[16]) % (1 << 32), 5) - (Q[15] ^ (Q[14] & (Q[16] ^ Q[15]))) - Q[13] - 0xf61e2562) % (
                                1 << 32)
                    Q[2] = (Q[1] + cls(((QM1 ^ (Q[1] & (QM0 ^ QM1))) + QM2 + x[1] + 0xe8c7b756) & 0xFFFFFFFF, 12)) & 0xFFFFFFFF
                    x[5] = (crs((Q[6] - Q[5]) % (1 << 32), 12) - (Q[3] ^ (Q[5] & (Q[4] ^ Q[3]))) - Q[2] - 0x4787c62a) % (1 << 32)
                    Q[21] = (Q[20] + cls(((Q[19] ^ (Q[18] & (Q[20] ^ Q[19]))) + Q[17] + x[5] + 0xd62f105d) & 0xFFFFFFFF,
                                         5)) & 0xFFFFFFFF
                    if ((Q[21] ^ Q[20]) & 0x80020000) != 0:
                        continue  # two conditions
                    Q[22] = (Q[21] + cls(((Q[20] ^ (Q[19] & (Q[21] ^ Q[20]))) + Q[18] + x[10] + 0x2441453) & 0xFFFFFFFF,
                                         9)) & 0xFFFFFFFF
                    if (Q[22] & longmask[32]) != bit_Q15_32:
                        continue  # one condition
                    x[15] = (crs((Q[16] - Q[15]) % (1 << 32), 22) - (Q[13] ^ (Q[15] & (Q[14] ^ Q[13]))) - Q[12] - 0x49b40821) % (
                                1 << 32)
                    zavorka_Q23 = ((Q[21] ^ (Q[20] & (Q[22] ^ Q[21]))) + Q[19] + x[15] + 0xd8a1e681) & 0xFFFFFFFF
                    if (zavorka_Q23 & longmask[18]) != 0:
                        continue
                    Q[23] = (Q[22] + cls(zavorka_Q23, 14)) & 0xFFFFFFFF
                    if (Q[23] & longmask[32]) != 0:
                        continue
                    x[4] = (crs((Q[5] - Q[4]) % (1 << 32), 7) - (Q[2] ^ (Q[4] & (Q[3] ^ Q[2]))) - Q[1] - 0xf57c0faf) % (1 << 32)
                    Q[24] = (Q[23] + cls(((Q[22] ^ (Q[21] & (Q[23] ^ Q[22]))) + Q[20] + x[4] + 0xe7d3fbc8) & 0xFFFFFFFF,
                                         20)) & 0xFFFFFFFF
                    if (Q[24] & longmask[32]) != longmask[32]:
                        continue
                    hQ3p = Q[3] & 0x77ffffda
                    hQ4p = Q[4] & 0x8bfffff5
                    hQ14p = Q[14] & 0xe3ffff88
                    constxx = ((crs((Q[7] - Q[6]) % (1 << 32), 17) - 0xa8304613
                                - crs((Q[18] - Q[17]) % (1 << 32), 9) - F(Q[6], Q[5], hQ4p)
                                - hQ3p) % (1 << 32)
                               + hQ14p + 0xc040b340 + (Q[16] ^ (Q[15] & (Q[17] ^ Q[16])))) & 0xFFFFFFFF

                    B1a = (crs((Q[13] - Q[12]) % (1 << 32), 7) - (Q[10] ^ (Q[12] & (Q[11] ^ Q[10]))) - 0x6b901122) % (1 << 32)
                    B1b = (Q[21] + 0x21e1cde6) & 0xFFFFFFFF
                    B1c = (x[5] + 0xfffa3942) & 0xFFFFFFFF
                    B1d = (x[1] + 0xa4beea44) & 0xFFFFFFFF
                    B1e = (x[15] + 0x1fa27cf8) & 0xFFFFFFFF
                    B1f = (x[5] + 0xfc93a039) & 0xFFFFFFFF

                    for Q14 in range(512):
                        constxxx = (constxx + maskQ14[Q14]) & 0xFFFFFFFF
                        if (constxxx & 0x03ffffd0) != 0:
                            continue
                        Q[4] = ((constxxx & 0x7400000a) + hQ4p) & 0xFFFFFFFF
                        Q[3] = ((constxxx & 0x88000025) + hQ3p) & 0xFFFFFFFF
                        x[2] = (crs((Q[3] - Q[2]) % (1 << 32), 17) - (QM0 ^ (Q[2] & (Q[1] ^ QM0))) - QM1 - 0x242070db) % (1 << 32)

                        B2a = (x[2] + 0xfcefa3f8) & 0xFFFFFFFF

                        for Q4 in range(1):  # tunnel Q4,26 not included

                            Q[4] = Q[4] ^ 0x02000000
                            x[4] = (crs((Q[5] - Q[4]) % (1 << 32), 7) - (Q[2] ^ (Q[4] & (Q[3] ^ Q[2]))) - Q[1] - 0xf57c0faf) % (
                                        1 << 32)
                            Q[24] = (Q[23] + cls(((Q[22] ^ (Q[21] & (Q[23] ^ Q[22]))) + Q[20] + x[4] + 0xe7d3fbc8) & 0xFFFFFFFF,
                                                 20)) & 0xFFFFFFFF
                            if (Q[24] & longmask[32]) != longmask[32]:
                                continue

                            Q[14] = (maskQ14[Q14] + hQ14p) & 0xFFFFFFFF

                            x[6] = (crs((Q[7] - Q[6]) % (1 << 32), 17) - (Q[4] ^ (Q[6] & (Q[5] ^ Q[4]))) - Q[3] - 0xa8304613) % (
                                        1 << 32)
                            # x[2] = (crs(Q[ 3]-Q[ 2],17) - F(Q[ 2],Q[ 1],  QM0) -   QM1 - 0x242070db) % (1 << 32)
                            x[3] = (crs((Q[4] - Q[3]) % (1 << 32), 22) - (Q[1] ^ (Q[3] & (Q[2] ^ Q[1]))) - QM0 - 0xc1bdceee) % (
                                        1 << 32)
                            x[7] = (crs((Q[8] - Q[7]) % (1 << 32), 22) - (Q[5] ^ (Q[7] & (Q[6] ^ Q[5]))) - Q[4] - 0xfd469501) % (
                                        1 << 32)
                            x[13] = (crs((Q[14] - Q[13]) % (1 << 32), 12) - (Q[11] ^ (Q[13] & (Q[12] ^ Q[11]))) - Q[
                                10] - 0xfd987193) % (1 << 32)
                            x[14] = (crs((Q[15] - Q[14]) % (1 << 32), 17) - (Q[12] ^ (Q[14] & (Q[13] ^ Q[12]))) - Q[
                                11] - 0xa679438e) % (1 << 32)

                            B3a = (Q[22] + x[14] + 0xc33707d6) & 0xFFFFFFFF
                            B3b = (Q[23] + x[3] + 0xf4d50d87) & 0xFFFFFFFF
                            B3c = (Q[24] + 0x455a14ed) & 0xFFFFFFFF
                            B3d = (x[13] + 0xa9e3e905) & 0xFFFFFFFF
                            B3e = (x[7] + 0x676f02d9) & 0xFFFFFFFF
                            B3f = (x[14] + 0xfde5380c) & 0xFFFFFFFF
                            B3g = (x[4] + 0x4bdecfa9) & 0xFFFFFFFF
                            B3h = (x[7] + 0xf6bb4b60) & 0xFFFFFFFF
                            B3i = (x[13] + 0x289b7ec6) & 0xFFFFFFFF
                            B3j = (x[3] + 0xd4ef3085) & 0xFFFFFFFF
                            B3k = (x[6] + 0x4881d05) & 0xFFFFFFFF
                            B3l = (x[2] + 0xc4ac5665) & 0xFFFFFFFF
                            B3m = (x[7] + 0x432aff97) & 0xFFFFFFFF
                            B3n = (x[14] + 0xab9423a7) & 0xFFFFFFFF

                            for Q9 in range(8):  # 8
                                Q[9] = tempq9 ^ mask_Q9[Q9]
                                # x[ 8] = (crs(Q[ 9]-Q[ 8], 7) - F(Q[ 8],Q[ 7],Q[ 6]) - Q[ 5] - 0x698098d8) % (1 << 32)
                                # B0a= F(Q[ 8],Q[ 7],Q[ 6]) + Q[ 5] + 0x698098d8
                                x[8] = (crs((Q[9] - Q[8]) % (1 << 32), 7) - B0a) % (1 << 32)
                                # x[ 9] = (crs((Q[10]-Q[9]) % (1 << 32) 9],12) - F(Q[ 9],Q[ 8],Q[ 7]) - Q[ 6] - 0x8b44f7af) % (1 << 32)
                                # B0b = (Q[ 6] + 0x8b44f7af) & 0xFFFFFFFF
                                x[9] = (crs((Q[10] - Q[9]) % (1 << 32), 12) - (Q[7] ^ (Q[9] & (Q[8] ^ Q[7]))) - B0b) % (1 << 32)
                                # x[12] = (crs((Q[13]-Q[12]) % (1 << 32), 7) - F(Q[12],Q[11],Q[10]) - Q[ 9] - 0x6b901122) % (1 << 32)
                                # B1a=crs((Q[13]-Q[12]) % (1 << 32), 7) - F(Q[12],Q[11],Q[10]) - 0x6b901122
                                x[12] = (B1a - Q[9]) % (1 << 32)
                                # Q[25] = (Q[24] + cls(G(Q[24],Q[23],Q[22]) + Q[21] + x[9] + 0x21e1cde6, 5)) & 0xFFFFFFFF
                                # B1b = (Q[21] + 0x21e1cde6) & 0xFFFFFFFF
                                Q[25] = (Q[24] + cls(((Q[23] ^ (Q[22] & (Q[24] ^ Q[23]))) + B1b + x[9]) & 0xFFFFFFFF,
                                                     5)) & 0xFFFFFFFF
                                # Q[26] = (Q[25] + cls(G(Q[25],Q[24],Q[23]) + Q[22] + x[14] + 0xc33707d6, 9)) & 0xFFFFFFFF
                                # B3a=Q[22] + x[14] + 0xc33707d6
                                Q[26] = (Q[25] + cls(((Q[24] ^ (Q[23] & (Q[25] ^ Q[24]))) + B3a) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
                                # Q[27] = (Q[26] + cls(G(Q[26],Q[25],Q[24]) + Q[23] + x[3] + 0xf4d50d87, 14)) & 0xFFFFFFFF
                                # B3b = (Q[23] + x[3] + 0xf4d50d87) & 0xFFFFFFFF
                                Q[27] = (Q[26] + cls(((Q[25] ^ (Q[24] & (Q[26] ^ Q[25]))) + B3b) & 0xFFFFFFFF, 14)) & 0xFFFFFFFF
                                # Q[28] = (Q[27] + cls(G(Q[27],Q[26],Q[25]) + Q[24] + x[8] + 0x455a14ed, 20)) & 0xFFFFFFFF
                                # B3c = (Q[24] + 0x455a14ed) & 0xFFFFFFFF
                                Q[28] = (Q[27] + cls(((Q[26] ^ (Q[25] & (Q[27] ^ Q[26]))) + x[8] + B3c) & 0xFFFFFFFF,
                                                     20)) & 0xFFFFFFFF
                                # Q[29] = (Q[28] + cls(G(Q[28],Q[27],Q[26]) + Q[25] + x[13] + 0xa9e3e905, 5)) & 0xFFFFFFFF
                                # B3d = (x[13] + 0xa9e3e905) & 0xFFFFFFFF
                                Q[29] = (Q[28] + cls(((Q[27] ^ (Q[26] & (Q[28] ^ Q[27]))) + Q[25] + B3d) & 0xFFFFFFFF,
                                                     5)) & 0xFFFFFFFF
                                # Q[30] = (Q[29] + cls( G(Q[29],Q[28],Q[27]) + Q[26] + x[2] + 0xfcefa3f8, 9)) & 0xFFFFFFFF
                                # B2a = (x[2] + 0xfcefa3f8) & 0xFFFFFFFF
                                Q[30] = (Q[29] + cls(((Q[28] ^ (Q[27] & (Q[29] ^ Q[28]))) + Q[26] + B2a) & 0xFFFFFFFF,
                                                     9)) & 0xFFFFFFFF
                                # Q[31] = (Q[30] + cls( G(Q[30],Q[29],Q[28]) + Q[27] + x[7] + 0x676f02d9, 14)) & 0xFFFFFFFF
                                # B3e = (x[7] + 0x676f02d9) & 0xFFFFFFFF
                                Q[31] = (Q[30] + cls(((Q[29] ^ (Q[28] & (Q[30] ^ Q[29]))) + Q[27] + B3e) & 0xFFFFFFFF,
                                                     14)) & 0xFFFFFFFF
                                Q[32] = (Q[31] + cls(
                                    ((Q[30] ^ (Q[29] & (Q[31] ^ Q[30]))) + Q[28] + x[12] + 0x8d2a4c8a) & 0xFFFFFFFF,
                                    20)) & 0xFFFFFFFF
                                # Q[33] = (Q[32] + cls( H(Q[32],Q[31],Q[30]) + Q[29] + x[5] +0xfffa3942, 4)) & 0xFFFFFFFF
                                # B1c = (x[5] +0xfffa3942) & 0xFFFFFFFF
                                Q[33] = (Q[32] + cls(((Q[32] ^ Q[31] ^ Q[30]) + Q[29] + B1c) & 0xFFFFFFFF,
                                                     4)) & 0xFFFFFFFF

                                Q[34] = (Q[33] + cls(((Q[33] ^ Q[32] ^ Q[31]) + Q[30] + x[8] + 0x8771f681) & 0xFFFFFFFF,
                                                     11)) & 0xFFFFFFFF

                                # bit 16 nulovy
                                zavorka_Q35 = ((Q[34] ^ Q[33] ^ Q[32]) + Q[31] + x[11] + 0x6d9d6122) & 0xFFFFFFFF

                                if (zavorka_Q35 & longmask[16]) != 0:
                                    continue

                                Q[35] = ((Q[34] + cls(zavorka_Q35, 16)) & 0xFFFFFFFF) & 0xFFFFFFFF
                                # Q[36] = (Q[35] + cls( H(Q[35],Q[34],Q[33]) + Q[32] + x[14] + 0xfde5380c, 23)) & 0xFFFFFFFF
                                # B3f = (x[14] + 0xfde5380c) & 0xFFFFFFFF
                                Q[36] = (Q[35] + cls(((Q[35] ^ Q[34] ^ Q[33]) + Q[32] + B3f) & 0xFFFFFFFF,
                                                     23)) & 0xFFFFFFFF
                                # Q[37] = (Q[36] + cls( H(Q[36],Q[35],Q[34]) + Q[33] + x[1] + 0xa4beea44, 4)) & 0xFFFFFFFF
                                # B1d = ( x[1] + 0xa4beea44) & 0xFFFFFFFF
                                Q[37] = (Q[36] + cls(((Q[36] ^ Q[35] ^ Q[34]) + Q[33] + B1d) & 0xFFFFFFFF,
                                                     4)) & 0xFFFFFFFF
                                # Q[38] = (Q[37] + cls( H(Q[37],Q[36],Q[35]) + Q[34] + x[4] + 0x4bdecfa9, 11)) & 0xFFFFFFFF
                                # B3g = (x[4] + 0x4bdecfa9) & 0xFFFFFFFF
                                Q[38] = (Q[37] + cls(((Q[37] ^ Q[36] ^ Q[35]) + Q[34] + B3g) & 0xFFFFFFFF,
                                                     11)) & 0xFFFFFFFF
                                # Q[39] = (Q[38] + cls( H(Q[38],Q[37],Q[36]) + Q[35] + x[7] + 0xf6bb4b60, 16)) & 0xFFFFFFFF
                                # B3h = (x[7] + 0xf6bb4b60) & 0xFFFFFFFF
                                Q[39] = (Q[38] + cls(((Q[38] ^ Q[37] ^ Q[36]) + Q[35] + B3h) & 0xFFFFFFFF,
                                                     16)) & 0xFFFFFFFF

                                # Q[40] = (Q[39] + cls( H(Q[39],Q[38],Q[37]) + Q[36] + x[10] +0xbebfbc70 , 23)) & 0xFFFFFFFF
                                # B01a = (	x[10] +0xbebfbc70) & 0xFFFFFFFF
                                Q[40] = (Q[39] + cls(((Q[39] ^ Q[38] ^ Q[37]) + Q[36] + B01a) & 0xFFFFFFFF,
                                                     23)) & 0xFFFFFFFF
                                # Q[41] = (Q[40] + cls( H(Q[40],Q[39],Q[38]) + Q[37] + x[13] + 0x289b7ec6, 4)) & 0xFFFFFFFF
                                # B3i = (x[13] + 0x289b7ec6) & 0xFFFFFFFF
                                Q[41] = (Q[40] + cls(((Q[40] ^ Q[39] ^ Q[38]) + Q[37] + B3i) & 0xFFFFFFFF,
                                                     4)) & 0xFFFFFFFF
                                # Q[42] = (Q[41] + cls( H(Q[41],Q[40],Q[39]) + Q[38] + x[0] + 0xeaa127fa, 11)) & 0xFFFFFFFF
                                # B02a = (x[0] + 0xeaa127fa) & 0xFFFFFFFF
                                Q[42] = (Q[41] + cls(((Q[41] ^ Q[40] ^ Q[39]) + Q[38] + B02a) & 0xFFFFFFFF,
                                                     11)) & 0xFFFFFFFF
                                # Q[43] = (Q[42] + cls( H(Q[42],Q[41],Q[40]) + Q[39] + x[3] + 0xd4ef3085, 16)) & 0xFFFFFFFF
                                # B3j = (x[3] + 0xd4ef3085) & 0xFFFFFFFF
                                Q[43] = (Q[42] + cls(((Q[42] ^ Q[41] ^ Q[40]) + Q[39] + B3j) & 0xFFFFFFFF,
                                                     16)) & 0xFFFFFFFF
                                # Q[44] = (Q[43] + cls( H(Q[43],Q[42],Q[41]) + Q[40] + x[6] + 0x4881d05, 23)) & 0xFFFFFFFF
                                # B3k = (x[6] + 0x4881d05) & 0xFFFFFFFF
                                Q[44] = (Q[43] + cls(((Q[43] ^ Q[42] ^ Q[41]) + Q[40] + B3k) & 0xFFFFFFFF,
                                                     23)) & 0xFFFFFFFF
                                Q[45] = (Q[44] + cls(((Q[44] ^ Q[43] ^ Q[42]) + Q[41] + x[9] + 0xd9d4d039) & 0xFFFFFFFF,
                                                     4)) & 0xFFFFFFFF
                                Q[46] = (Q[45] + cls(((Q[45] ^ Q[44] ^ Q[43]) + Q[42] + x[12] + 0xe6db99e5) & 0xFFFFFFFF,
                                                     11)) & 0xFFFFFFFF

                                # Q[47] = (Q[46] + cls( H(Q[46],Q[45],Q[44]) + Q[43] + x[15] + 0x1fa27cf8, 16)) & 0xFFFFFFFF
                                # B1e = (x[15] + 0x1fa27cf8) & 0xFFFFFFFF
                                Q[47] = (Q[46] + cls(((Q[46] ^ Q[45] ^ Q[44]) + Q[43] + B1e) & 0xFFFFFFFF,
                                                     16)) & 0xFFFFFFFF
                                # Q[48] = (Q[47] + cls( H(Q[47],Q[46],Q[45]) + Q[44] + x[2] + 0xc4ac5665, 23)) & 0xFFFFFFFF
                                # B3l = (x[2] + 0xc4ac5665) & 0xFFFFFFFF
                                Q[48] = (Q[47] + cls(((Q[47] ^ Q[46] ^ Q[45]) + Q[44] + B3l) & 0xFFFFFFFF,
                                                     23)) & 0xFFFFFFFF

                                bitI = Q[46] & longmask[32]

                                if (Q[48] & longmask[32]) != bitI:
                                    continue

                                # Q[49] = (Q[48] + cls( I(Q[48],Q[47],Q[46]) + Q[45] + x[0] + 0xf4292244, 6)) & 0xFFFFFFFF
                                # B02b = (x[0] + 0xf4292244) & 0xFFFFFFFF
                                Q[49] = (Q[48] + cls(((Q[47] ^ (Q[48] | ~Q[46])) + Q[45] + B02b) & 0xFFFFFFFF,
                                                     6)) & 0xFFFFFFFF

                                bitJ = Q[47] & longmask[32]

                                if (Q[49] & longmask[32]) != bitJ:
                                    continue

                                # Q[50] = (Q[49] + cls( I(Q[49],Q[48],Q[47]) + Q[46]  + x[7] + 0x432aff97, 10)) & 0xFFFFFFFF
                                # B3m = (x[7] + 0x432aff97) & 0xFFFFFFFF
                                Q[50] = (Q[49] + cls(((Q[48] ^ (Q[49] | ~Q[47])) + Q[46] + B3m) & 0xFFFFFFFF,
                                                     10)) & 0xFFFFFFFF

                                bit_I_neg = bitI ^ longmask[32]

                                if (Q[50] & longmask[32]) != bit_I_neg:
                                    continue

                                # Q[51] = (Q[50] + cls( I(Q[50],Q[49],Q[48]) + Q[47] + x[14] + 0xab9423a7, 15)) & 0xFFFFFFFF
                                # B3n = (x[14] + 0xab9423a7) & 0xFFFFFFFF
                                Q[51] = (Q[50] + cls(((Q[49] ^ (Q[50] | ~Q[48])) + Q[47] + B3n) & 0xFFFFFFFF,
                                                     15)) & 0xFFFFFFFF
                                if (Q[51] & longmask[32]) != bitJ:
                                    continue
                                # Q[52] = (Q[51] + cls( I(Q[51],Q[50],Q[49]) + Q[48] + x[5] + 0xfc93a039, 21)) & 0xFFFFFFFF
                                # B1f = (x[5] + 0xfc93a039) & 0xFFFFFFFF
                                Q[52] = (Q[51] + cls(((Q[50] ^ (Q[51] | ~Q[49])) + Q[48] + B1f) & 0xFFFFFFFF,
                                                     21)) & 0xFFFFFFFF

                                if (Q[52] & longmask[32]) != bit_I_neg:
                                    continue
                                Q[53] = (Q[52] + cls(
                                    ((Q[51] ^ (Q[52] | ~Q[50])) + Q[49] + x[12] + 0x655b59c3) & 0xFFFFFFFF, 6)) & 0xFFFFFFFF
                                if (Q[53] & longmask[32]) != bitJ:
                                    continue
                                Q[54] = (Q[53] + cls(((Q[52] ^ (Q[53] | ~Q[51])) + Q[50] + x[3] + 0x8f0ccc92) & 0xFFFFFFFF,
                                                     10)) & 0xFFFFFFFF
                                if (Q[54] & longmask[32]) != bit_I_neg:
                                    continue
                                Q[55] = (Q[54] + cls(((Q[53] ^ (Q[54] | ~Q[52])) + Q[51] + x[10] + 0xffeff47d) & 0xFFFFFFFF,
                                                     15)) & 0xFFFFFFFF
                                if (Q[55] & longmask[32]) != bitJ:
                                    continue
                                Q[56] = (Q[55] + cls(((Q[54] ^ (Q[55] | ~Q[53])) + Q[52] + x[1] + 0x85845dd1) & 0xFFFFFFFF,
                                                     21)) & 0xFFFFFFFF
                                if (Q[56] & longmask[32]) != bit_I_neg:
                                    continue
                                Q[57] = (Q[56] + cls(((Q[55] ^ (Q[56] | ~Q[54])) + Q[53] + x[8] + 0x6fa87e4f) & 0xFFFFFFFF,
                                                     6)) & 0xFFFFFFFF
                                if (Q[57] & longmask[32]) != bitJ:
                                    continue
                                Q[58] = (Q[57] + cls(((Q[56] ^ (Q[57] | ~Q[55])) + Q[54] + x[15] + 0xfe2ce6e0) & 0xFFFFFFFF,
                                                     10)) & 0xFFFFFFFF
                                if (Q[58] & longmask[32]) != bit_I_neg:
                                    continue
                                Q[59] = (Q[58] + cls(((Q[57] ^ (Q[58] | ~Q[56])) + Q[55] + x[6] + 0xa3014314) & 0xFFFFFFFF,
                                                     15)) & 0xFFFFFFFF
                                if (Q[59] & longmask[32]) != bitJ:
                                    continue
                                Q[60] = (Q[59] + cls(((Q[58] ^ (Q[59] | ~Q[57])) + Q[56] + x[13] + 0x4e0811a1) & 0xFFFFFFFF,
                                                     21)) & 0xFFFFFFFF
                                if (Q[60] & longmask[32]) != bitI:
                                    continue
                                if (Q[60] & longmask[26]) != 0:
                                    continue
                                Q[61] = (Q[60] + cls(((Q[59] ^ (Q[60] | ~Q[58])) + Q[57] + x[4] + 0xf7537e82) & 0xFFFFFFFF,
                                                     6)) & 0xFFFFFFFF
                                if (Q[61] & longmask[32]) != bitJ:
                                    continue
                                if (Q[61] & longmask[26]) != longmask[26]:
                                    continue
                                zavorka_Q62 = ((Q[60] ^ (Q[61] | ~Q[59])) + Q[58] + x[11] + 0xbd3af235) & 0xFFFFFFFF
                                Q[62] = (Q[61] + cls(zavorka_Q62, 10)) & 0xFFFFFFFF
                                Q[63] = (Q[62] + cls(((Q[61] ^ (Q[62] | ~Q[60])) + Q[59] + x[2] + 0x2ad7d2bb) & 0xFFFFFFFF,
                                                     15)) & 0xFFFFFFFF
                                Q[64] = (Q[63] + cls(((Q[62] ^ (Q[63] | ~Q[61])) + Q[60] + x[9] + 0xeb86d391) & 0xFFFFFFFF,
                                                     21)) & 0xFFFFFFFF

                                AA0 = IHV1[0] = (IHV0[0] + Q[61]) & 0xFFFFFFFF
                                DD0 = IHV1[3] = (IHV0[3] + Q[62]) & 0xFFFFFFFF
                                CC0 = IHV1[2] = (IHV0[2] + Q[63]) & 0xFFFFFFFF
                                BB0 = IHV1[1] = (IHV0[1] + Q[64]) & 0xFFFFFFFF
                                if (DD0 & longmask[26]) != 0:
                                    continue
                                if (CC0 & longmask[26]) != longmask[26]:
                                    continue
                                if (CC0 & longmask[27]) != 0:
                                    continue
                                if ((CC0 ^ DD0) & longmask[32]) != 0:
                                    continue

                                if (BB0 & longmask[6]) != 0:
                                    continue
                                if (BB0 & longmask[26]) != 0:
                                    continue
                                if (BB0 & longmask[27]) != 0:
                                    continue
                                if ((BB0 ^ CC0) & longmask[32]) != 0:
                                    continue

                                # NEW: Curly brackets
                                M = x.copy()

                                M[4] = (x[4] + 0x80000000) & 0xFFFFFFFF
                                M[11] = (x[11] + 0x00008000) & 0xFFFFFFFF
                                M[14] = (x[14] + 0x80000000) & 0xFFFFFFFF

                                HIHV0 = IHV0.copy()
                                md5.compress(HIHV0, M)  # mit a, b, c, d und M
                                HIHV1 = HIHV0.copy()

                                print(f"Block1: {os.getpid()}")
                                print((HIHV1[0] - IHV1[0] - 0x80000000) % (1 << 32))
                                print((HIHV1[1] - IHV1[1] - 0x82000000) % (1 << 32))
                                print((HIHV1[2] - IHV1[2] - 0x82000000) % (1 << 32))
                                print((HIHV1[3] - IHV1[3] - 0x82000000) % (1 << 32))
                                if (((HIHV1[0] - IHV1[0] - 0x80000000) % (1 << 32)) != 0 or
                                        ((HIHV1[1] - IHV1[1] - 0x82000000) % (1 << 32)) != 0 or
                                        ((HIHV1[2] - IHV1[2] - 0x82000000) % (1 << 32)) != 0 or
                                        ((HIHV1[3] - IHV1[3] - 0x82000000) % (1 << 32)) != 0):
                                    continue

                                global P_IHV1, P_HIHV1, x1, M1
                                P_IHV1 = IHV1.copy()
                                P_HIHV1 = HIHV1.copy()
                                x1 = x.copy()
                                M1 = M.copy()

                                # GetLocalTime(&now)
                                time1 = time.perf_counter() - startTime
                                # printf("%02d.%02d.%04d %02d:%02d:%02d.%03d\n",
                                # now.wDay,now.wMonth,now.wYear,
                                # now.wHour,now.wMinute,now.wSecond,now.wMilliseconds)
                                #
                                print(f"The first block collision took {time1} second")

                                # fcb = fopen( out_filename,"a" )
                                # fprintf(fcb,"\n The first block collision took  : %f sec\n", time1)
                                # sprintf(buffer,"%02d.%02d.%04d %02d:%02d:%02d.%03d\n",
                                # now.wDay,now.wMonth,now.wYear,
                                # now.wHour,now.wMinute,now.wSecond,now.wMilliseconds)
                                # fwrite(buffer,1,strlen(buffer),fcb)
                                # fclose( fcb )
                                #
                                # startTime = time.perf_counter()

                                while True:
                                    if not findBlock2():
                                        break

                                time2 = time.perf_counter() - time1 - startTime
                                print(f"The second block collision took {time2} second")

                                global collision_count, time3, time4, time5, x2, M2, Q2
                                collision_count += 1
                                time3 += time1 + time2
                                time4 += time1
                                time5 += time2
                                result = [f"{os.getpid()} @ {datetime.now().strftime('%d.%m.%Y-%H:%M:%S')}",
                                          f"IV: {', '.join('0x{:08x}'.format(num) for num in IHV0)}",
                                          f"Hash digest: {', '.join('0x{:08x}'.format(num) for num in hashDigest)}",
                                          f"m1: {', '.join('0x{:08x}'.format(num) for num in x1)}, {', '.join('0x{:08x}'.format(num) for num in x2)}",
                                          f"m2: {', '.join('0x{:08x}'.format(num) for num in M1)}, {', '.join('0x{:08x}'.format(num) for num in M2)}",
                                          f"Q: {', '.join('0x{:08x}'.format(num) for num in Q)}",
                                          f"Q2: {', '.join('0x{:08x}'.format(num) for num in Q2)}",
                                          f"1st block: {time1}",
                                          f"2nd block: {time2}",
                                          f"AVERAGE 1st block: {time4 / collision_count}",
                                          f"AVERAGE 2nd block: {time5 / collision_count}",
                                          f"AVERAGE time for {collision_count} collisions: {time3 / collision_count}"]
                                filePath = os.path.join(os.getcwd(), "collisions", f"collisions_{now}.txt")
                                with open(filePath, "a+") as file:
                                    file.write(f"{result}\n")
                                    file.close()
                                return 0
    return -1  # collision not found


# =========================================================
def findBlock2():
    Q = [0] * 65
    x = [0] * 16

    QM3 = P_IHV1[0]
    QM2 = P_IHV1[3]
    QM1 = CC0 = P_IHV1[2]
    QM0 = BB0 = P_IHV1[1]
    bitI = BB0 & longmask[32]
    bit_neg_I = (~BB0) & longmask[32]

    #  a1
    # Q[ 1]         =~Ivvv 010v vv1v vvv1 .vvv 0vvv vv0. ...v
    # position with RNG  = .*** ...* **.* ***. **** .*** **.* ****  0x71def7df
    # position with 0    = .... *.*. .... .... .... *... ..*. ....  0x0a000820
    # position with 1    = .... .*.. ..*. ...* .... .... .... ....  0x04210000
    Q[1] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x71def7df) + 0x04210000

    #  d1
    # Multi message modif. meth. (MMMM) Q1Q2, Klima
    # Q[ 2]         =~I^^^ 110^ ^^0^ ^^^1 0^^^ 1^^^ ^^0v v00^
    # position with RNG  = .... .... .... .... .... .... ...* *...  0x00000018
    # position with 0    = .... ..*. ..*. .... *... .... ..*. .**.  0x02208026
    # position with 1    = .... **.. .... ...* .... *... .... ....  0x0c010800
    # position with Q[ 1]= .*** ...* **.* ***. .*** .*** **.. ...*  0x71de77c1
    Q[2] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x00000018) + 0x0c010800 + (Q[1] & 0x71de77c1)

    #  c1
    # Q[ 3]         =~I011 111. ..01 1111 1..0 1vv1 011^ ^111
    # position with RNG  = .... ...* **.. .... .**. .**. .... ....  0x01c06600
    # position with 0    = .*.. .... ..*. .... ...* .... *... ....  0x40201080
    # position with 1    = ..** ***. ...* **** *... *..* .**. .***  0x3e1f8967
    # position with Q[ 2]= .... .... .... .... .... .... ...* *...  0x00000018
    Q[3] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x01c06600) + 0x3e1f8967 + (Q[2] & 0x00000018)

    #  b1
    # Q[ 4]         =~I011 101. ..00 0100 ...0 0^^0 0001 0001
    # position with RNG  = .... ...* **.. .... ***. .... .... ....  0x01c0e000
    # position with 0    = .*.. .*.. ..** *.** ...* *..* ***. ***.  0x443b19ee
    # position with 1    = ..** *.*. .... .*.. .... .... ...* ...*  0x3a040011
    # position with Q[ 3]= .... .... .... .... .... .**. .... ....  0x00000600
    Q[4] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x01c0e000) + 0x3a040011 + (Q[3] & 0x00000600)

    #  a2
    # Q4 tunnel, Klima, bits 25-23,16-14
    # Q[ 5]         = I100 10.0 0010 1111 0000 1110 0101 0000
    # position with RNG  = .... ..*. .... .... .... .... .... ....  0x02000000
    # position with 0    = ..** .*.* **.* .... **** ...* *.*. ****  0x35d0f1af
    # position with 1    = .*.. *... ..*. **** .... ***. .*.* ....  0x482f0e50
    Q[5] = bitI + (random.randint(0, (2 ** 32) - 1) & 0x02000000) + 0x482f0e50

    # d2
    # Q4 tunnel, Klima, bits 25-23,16-14
    # Q[ 6]         = I..0 0101 1110 ..10 1110 1100 0101 0110
    # position with RNG  = .**. .... .... **.. .... .... .... ....  0x600c0000
    # position with 0    = ...* *.*. ...* ...* ...* ..** *.*. *..*  0x1a1113a9
    # position with 1    = .... .*.* ***. ..*. ***. **.. .*.* .**.  0x05e2ec56
    Q[6] = bitI + (random.randint(0, (2 ** 32) - 1) & 0x600c0000) + 0x05e2ec56

    # c2
    # Q[ 7]         =~I..1 0111 1.00 ..01 10.1 1110 00.. ..v1
    # position with RNG  = .**. .... .*.. **.. ..*. .... ..** ***.  0x604c203e
    # position with 0    = .... *... ..** ..*. .*.. ...* **.. ....  0x083241c0
    # position with 1    = ...* .*** *... ...* *..* ***. .... ...*  0x17819e01
    Q[7] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x604c203e) + 0x17819e01

    # b2
    # Q[ 8]         =~I..0 0100 0.11 ..10 1..v ..11 111. ..^0
    # position with RNG  = .**. .... .*.. **.. .*** **.. ...* **..  0x604c7c1c
    # position with 0    = ...* *.** *... ...* .... .... .... ...*  0x1b810001
    # position with 1    = .... .*.. ..** ..*. *... ..** ***. ....  0x043283e0
    # position with Q[ 7]= .... .... .... .... .... .... .... ..*.  0x00000002
    Q[8] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x604c7c1c) + 0x043283e0 + (Q[7] & 0x00000002)
    # a3
    # Q9 tunnel plus MMMM-Q12Q11, Klima, prepared, not programmed
    # Q[ 9]         =~Ivv1 1100 0xxx .x01 0..^ .x01 110x xx01
    # position with RNG  = .**. .... .*** **.. .**. **.. ...* **..  0x607c6c1c
    # position with 0    = .... ..** *... ..*. *... ..*. ..*. ..*.  0x03828222
    # position with 1    = ...* **.. .... ...* .... ...* **.. ...*  0x1c0101c1
    # position with Q[ 8]= .... .... .... .... ...* .... .... ....  0x00001000
    Q[9] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x607c6c1c) + 0x1c0101c1 + (Q[8] & 0x00001000)

    #  d3
    # Q9 tunnel plus MMMM-Q12Q11, Klima
    # Q[10]         =~I^^1 1111 1000 v011 1vv0 1011 1100 0000
    # position with RNG  = .... .... .... *... .**. .... .... ....  0x00086000
    # position with 0    = .... .... .*** .*.. ...* .*.. ..** ****  0x0074143f
    # position with 1    = ...* **** *... ..** *... *.** **.. ....  0x1f838bc0
    # position with Q[ 9]= .**. .... .... .... .... .... .... ....  0x60000000
    Q[10] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x00086000) + 0x1f838bc0 + (Q[9] & 0x60000000)
    # c3
    # Q9 tunnel plus MMMM-Q12Q11, Klima
    # Q[11]         =~Ivvv vvvv .111 ^101 1^^0 0111 11v1 1111
    # position with RNG  = .*** **** *... .... .... .... ..*. ....  0x7f800020
    # position with 0    = .... .... .... ..*. ...* *... .... ....  0x00021800
    # position with 1    = .... .... .*** .*.* *... .*** **.* ****  0x007587df
    # position with Q[10]= .... .... .... *... .**. .... .... ....  0x00086000
    Q[11] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x7f800020) + 0x007587df + (Q[10] & 0x00086000)
    # b3
    # MMMM-Q12Q11, Klima
    # Q[12]         =~I^^^ ^^^^ .... 1000 0001 .... 1.^. ....
    # position with RNG  = .... .... **** .... .... **** .*.* ****  0x00f00f5f
    # position with 0    = .... .... .... .*** ***. .... .... ....  0x0007e000
    # position with 1    = .... .... .... *... ...* .... *... ....  0x00081080
    # position with Q[11]= .*** **** .... .... .... .... ..*. ....  0x7f000020
    Q[12] = bit_neg_I + (random.randint(0, (2 ** 32) - 1) & 0x00f00f5f) + 0x00081080 + (Q[11] & 0x7f000020)
    #  a4
    # Q[13]         = I011 1111 0... 1111 111. .... 0... 1...
    # position with RNG  = .... .... .*** .... ...* **** .*** .***  0x00701f77
    # position with 0    = .*.. .... *... .... .... .... *... ....  0x40800080
    # position with 1    = ..** **** .... **** ***. .... .... *...  0x3f0fe008
    Q[13] = bitI + (random.randint(0, (2 ** 32) - 1) & 0x00701f77) + 0x3f0fe008
    # d4
    # Q[14]         = I100 0000 1... 1011 111. .... 1... 1...
    # position with RNG  = .... .... .*** .... ...* **** .*** .***  0x00701f77
    # position with 0    = ..** **** .... .*.. .... .... .... ....  0x3f040000
    # position with 1    = .*.. .... *... *.** ***. .... *... *...  0x408be088
    Q[14] = bitI + (random.randint(0, (2 ** 32) - 1) & 0x00701f77) + 0x408be088
    # c4
    # Q[15]         = 0111 1101 .... ..10 00.. .... .... 0...
    # position with RNG  = .... .... **** **.. ..** **** **** .***  0x00fc3ff7
    # position with 0    = *... ..*. .... ...* **.. .... .... *...  0x8201c008
    # position with 1    = .*** **.* .... ..*. .... .... .... ....  0x7d020000
    # Q[15] = (( (random.randint(0, (2 ** 32) - 1) & 0x00fc3ff7) +  0x7d020000) & 0xFFFFFFFF) % (1 << 32)

    # b4
    # Q[16]         = ^.10 .... .... ..01 1... .... .... 1...
    # position with RNG  = .*.. **** **** **.. .*** **** **** .***  0x4ffc7ff7
    # position with 0    = ...* .... .... ..*. .... .... .... ....  0x10020000
    # position with 1    = ..*. .... .... ...* *... .... .... *...  0x20018008
    # position with Q[15]= *......................................  0x80000000
    # Q[16] = (( (random.randint(0, (2 ** 32) - 1) & 0x4ffc7ff7) + 0x20018008) & 0xFFFFFFFF) % (1 << 32)

    spolecna_maska = 0x71de77c1 & (~(BB0 ^ CC0))
    jednicky = 0
    for i in range(33):
        if (spolecna_maska & longmask[i]) != 0:
            jednicky += 1

    tQ1 = Q[1] & ~spolecna_maska
    tQ2 = Q[2] & ~spolecna_maska
    temp2Q1 = Q[1]
    temp2Q2 = Q[2]
    temp2Q4 = Q[4]
    temp2Q9 = Q[9]

    for cq16 in range(longmask[26]):
        Q[1] = temp2Q1
        Q[2] = temp2Q2
        Q[4] = temp2Q4
        Q[9] = temp2Q9

        Q[15] = (random.randint(0, (2 ** 32) - 1) & 0x00fc3ff7) + 0x7d020000
        Q[16] = (random.randint(0, (2 ** 32) - 1) & 0x4ffc7ff7) + 0x20018008

        x[1] = (crs((Q[2] - Q[1]) % (1 << 32), 12) - (QM1 ^ (Q[1] & (QM0 ^ QM1))) - QM2 - 0xe8c7b756) % (1 << 32)
        zavorka_Q17 = ((Q[15] ^ (Q[14] & (Q[16] ^ Q[15]))) + Q[13] + x[1] + 0xf61e2562) & 0xFFFFFFFF
        if (zavorka_Q17 & 0x07000000) == 0x07000000:
            continue
        Q[17] = (Q[16] + cls(zavorka_Q17, 5)) & 0xFFFFFFFF
        if ((Q[17] ^ Q[16]) & 0x80028008) != 0:
            continue
        x[6] = (crs((Q[7] - Q[6]) % (1 << 32), 17) - (Q[4] ^ (Q[6] & (Q[5] ^ Q[4]))) - Q[3] - 0xa8304613) % (1 << 32)
        Q[18] = (Q[17] + cls(((Q[16] ^ (Q[15] & (Q[17] ^ Q[16]))) + Q[14] + x[6] + 0xc040b340) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
        if ((Q[18] ^ Q[17]) & 0xa0020000) != 0x00020000:
            continue

        x[11] = (crs((Q[12] - Q[11]) % (1 << 32), 22) - (Q[9] ^ (Q[11] & (Q[10] ^ Q[9]))) - Q[8] - 0x895cd7be) % (1 << 32)

        zavorka_Q19 = ((Q[17] ^ (Q[16] & (Q[18] ^ Q[17]))) + Q[15] + x[11] + 0x265e5a51) & 0xFFFFFFFF
        if (zavorka_Q19 & 0x0003fff8) == 0x0003fff8:
            continue

        Q[19] = (Q[18] + cls(zavorka_Q19, 14)) & 0xFFFFFFFF
        if (Q[19] & longmask[32]) != 0:
            continue
        if (Q[19] & longmask[18]) != 0:
            continue
        x[10] = (crs((Q[11] - Q[10]) % (1 << 32), 17) - (Q[8] ^ (Q[10] & (Q[9] ^ Q[8]))) - Q[7] - 0xffff5bb1) % (1 << 32)
        x[15] = (crs((Q[16] - Q[15]) % (1 << 32), 22) - (Q[13] ^ (Q[15] & (Q[14] ^ Q[13]))) - Q[12] - 0x49b40821) % (1 << 32)

        for cq1q2 in range(longmask[jednicky + 1]):

            Q[4] = temp2Q4
            Q[9] = temp2Q9

            Q[1] = ((random.randint(0, (2 ** 32) - 1) & spolecna_maska) + tQ1) & 0xFFFFFFFF
            Q[2] = ((Q[1] & spolecna_maska) + tQ2) & 0xFFFFFFFF
            x[0] = (crs((Q[1] - QM0) % (1 << 32), 7) - (QM2 ^ (QM0 & (QM1 ^ QM2))) - QM3 - 0xd76aa478) % (1 << 32)
            zavorka_Q20 = ((Q[18] ^ (Q[17] & (Q[19] ^ Q[18]))) + Q[16] + x[0] + 0xe9b6c7aa) & 0xFFFFFFFF
            if (zavorka_Q20 & 0xe0000000) == 0:
                continue
            Q[20] = (Q[19] + cls(zavorka_Q20, 20)) & 0xFFFFFFFF
            if (Q[20] & longmask[32]) != 0:
                continue
            x[5] = (crs((Q[6] - Q[5]) % (1 << 32), 12) - (Q[3] ^ (Q[5] & (Q[4] ^ Q[3]))) - Q[2] - 0x4787c62a) % (1 << 32)
            Q[21] = (Q[20] + cls(((Q[19] ^ (Q[18] & (Q[20] ^ Q[19]))) + Q[17] + x[5] + 0xd62f105d) & 0xFFFFFFFF, 5)) & 0xFFFFFFFF
            if ((Q[21] ^ Q[20]) & 0x80020000) != 0:
                continue
            Q[22] = (Q[21] + cls(((Q[20] ^ (Q[19] & (Q[21] ^ Q[20]))) + Q[18] + x[10] + 0x2441453) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
            if (Q[22] & longmask[32]) != 0:
                continue
            zavorka_Q23 = ((Q[21] ^ (Q[20] & (Q[22] ^ Q[21]))) + Q[19] + x[15] + 0xd8a1e681) & 0xFFFFFFFF
            if (zavorka_Q23 & longmask[18]) != 0:
                continue
            Q[23] = (Q[22] + cls(zavorka_Q23, 14)) & 0xFFFFFFFF
            if (Q[23] & longmask[32]) != 0:
                continue
            x[4] = (crs((Q[5] - Q[4]) % (1 << 32), 7) - (Q[2] ^ (Q[4] & (Q[3] ^ Q[2]))) - Q[1] - 0xf57c0faf) % (1 << 32)
            Q[24] = (Q[23] + cls(((Q[22] ^ (Q[21] & (Q[23] ^ Q[22]))) + Q[20] + x[4] + 0xe7d3fbc8) & 0xFFFFFFFF, 20)) & 0xFFFFFFFF
            if (Q[24] & longmask[32]) != longmask[32]:
                continue

            x[2] = (crs((Q[3] - Q[2]) % (1 << 32), 17) - (QM0 ^ (Q[2] & (Q[1] ^ QM0))) - QM1 - 0x242070db) % (1 << 32)
            x[13] = (crs((Q[14] - Q[13]) % (1 << 32), 12) - (Q[11] ^ (Q[13] & (Q[12] ^ Q[11]))) - Q[10] - 0xfd987193) % (1 << 32)
            x[14] = (crs((Q[15] - Q[14]) % (1 << 32), 17) - (Q[12] ^ (Q[14] & (Q[13] ^ Q[12]))) - Q[11] - 0xa679438e) % (1 << 32)

            for cq4 in range(64):

                Hi = (cq4 & 0x38) << 19
                Lo = (cq4 & 0x7) << 13

                Q[4] = ((temp2Q4 & ~0x01c0e000) + Hi + Lo) & 0xFFFFFFFF

                x[4] = (crs((Q[5] - Q[4]) % (1 << 32), 7) - (Q[2] ^ (Q[4] & (Q[3] ^ Q[2]))) - Q[1] - 0xf57c0faf) % (1 << 32)
                Q[24] = (Q[23] + cls(((Q[22] ^ (Q[21] & (Q[23] ^ Q[22]))) + Q[20] + x[4] + 0xe7d3fbc8) & 0xFFFFFFFF,
                                     20)) & 0xFFFFFFFF
                if (Q[24] & longmask[32]) != longmask[32]:
                    continue

                x[3] = (crs((Q[4] - Q[3]) % (1 << 32), 22) - (Q[1] ^ (Q[3] & (Q[2] ^ Q[1]))) - QM0 - 0xc1bdceee) % (1 << 32)
                x[7] = (crs((Q[8] - Q[7]) % (1 << 32), 22) - (Q[5] ^ (Q[7] & (Q[6] ^ Q[5]))) - Q[4] - 0xfd469501) % (1 << 32)
                for cq9 in range(256):

                    Q[9] = temp2Q9 ^ mask2Q9[cq9]
                    x[8] = (crs((Q[9] - Q[8]) % (1 << 32), 7) - (Q[6] ^ (Q[8] & (Q[7] ^ Q[6]))) - Q[5] - 0x698098d8) % (1 << 32)
                    x[9] = (crs((Q[10] - Q[9]) % (1 << 32), 12) - (Q[7] ^ (Q[9] & (Q[8] ^ Q[7]))) - Q[6] - 0x8b44f7af) % (1 << 32)
                    x[12] = (crs((Q[13] - Q[12]) % (1 << 32), 7) - (Q[10] ^ (Q[12] & (Q[11] ^ Q[10]))) - Q[9] - 0x6b901122) % (
                                1 << 32)

                    Q[25] = (Q[24] + cls(((Q[23] ^ (Q[22] & (Q[24] ^ Q[23]))) + Q[21] + x[9] + 0x21e1cde6) & 0xFFFFFFFF,
                                         5)) & 0xFFFFFFFF
                    Q[26] = (Q[25] + cls(((Q[24] ^ (Q[23] & (Q[25] ^ Q[24]))) + Q[22] + x[14] + 0xc33707d6) & 0xFFFFFFFF,
                                         9)) & 0xFFFFFFFF
                    Q[27] = (Q[26] + cls(((Q[25] ^ (Q[24] & (Q[26] ^ Q[25]))) + Q[23] + x[3] + 0xf4d50d87) & 0xFFFFFFFF,
                                         14)) & 0xFFFFFFFF
                    Q[28] = (Q[27] + cls(((Q[26] ^ (Q[25] & (Q[27] ^ Q[26]))) + Q[24] + x[8] + 0x455a14ed) & 0xFFFFFFFF,
                                         20)) & 0xFFFFFFFF
                    Q[29] = (Q[28] + cls(((Q[27] ^ (Q[26] & (Q[28] ^ Q[27]))) + Q[25] + x[13] + 0xa9e3e905) & 0xFFFFFFFF,
                                         5)) & 0xFFFFFFFF
                    Q[30] = (Q[29] + cls(((Q[28] ^ (Q[27] & (Q[29] ^ Q[28]))) + Q[26] + x[2] + 0xfcefa3f8) & 0xFFFFFFFF,
                                         9)) & 0xFFFFFFFF
                    Q[31] = (Q[30] + cls(((Q[29] ^ (Q[28] & (Q[30] ^ Q[29]))) + Q[27] + x[7] + 0x676f02d9) & 0xFFFFFFFF,
                                         14)) & 0xFFFFFFFF
                    Q[32] = (Q[31] + cls(((Q[30] ^ (Q[29] & (Q[31] ^ Q[30]))) + Q[28] + x[12] + 0x8d2a4c8a) & 0xFFFFFFFF,
                                         20)) & 0xFFFFFFFF
                    Q[33] = (Q[32] + cls(((Q[32] ^ Q[31] ^ Q[30]) + Q[29] + x[5] + 0xfffa3942) & 0xFFFFFFFF,
                                         4)) & 0xFFFFFFFF
                    Q[34] = (Q[33] + cls(((Q[33] ^ Q[32] ^ Q[31]) + Q[30] + x[8] + 0x8771f681) & 0xFFFFFFFF,
                                         11)) & 0xFFFFFFFF

                    zavorka_Q35 = ((Q[34] ^ Q[33] ^ Q[32]) + Q[31] + x[11] + 0x6d9d6122) & 0xFFFFFFFF
                    if (zavorka_Q35 & longmask[16]) != longmask[16]:
                        continue
                    Q[35] = (Q[34] + cls(zavorka_Q35, 16)) & 0xFFFFFFFF

                    Q[36] = (Q[35] + cls(((Q[35] ^ Q[34] ^ Q[33]) + Q[32] + x[14] + 0xfde5380c) & 0xFFFFFFFF,
                                         23)) & 0xFFFFFFFF
                    Q[37] = (Q[36] + cls(((Q[36] ^ Q[35] ^ Q[34]) + Q[33] + x[1] + 0xa4beea44) & 0xFFFFFFFF,
                                         4)) & 0xFFFFFFFF
                    Q[38] = (Q[37] + cls(((Q[37] ^ Q[36] ^ Q[35]) + Q[34] + x[4] + 0x4bdecfa9) & 0xFFFFFFFF,
                                         11)) & 0xFFFFFFFF
                    Q[39] = (Q[38] + cls(((Q[38] ^ Q[37] ^ Q[36]) + Q[35] + x[7] + 0xf6bb4b60) & 0xFFFFFFFF,
                                         16)) & 0xFFFFFFFF
                    Q[40] = (Q[39] + cls(((Q[39] ^ Q[38] ^ Q[37]) + Q[36] + x[10] + 0xbebfbc70) & 0xFFFFFFFF,
                                         23)) & 0xFFFFFFFF
                    Q[41] = (Q[40] + cls(((Q[40] ^ Q[39] ^ Q[38]) + Q[37] + x[13] + 0x289b7ec6) & 0xFFFFFFFF,
                                         4)) & 0xFFFFFFFF
                    Q[42] = (Q[41] + cls(((Q[41] ^ Q[40] ^ Q[39]) + Q[38] + x[0] + 0xeaa127fa) & 0xFFFFFFFF,
                                         11)) & 0xFFFFFFFF
                    Q[43] = (Q[42] + cls(((Q[42] ^ Q[41] ^ Q[40]) + Q[39] + x[3] + 0xd4ef3085) & 0xFFFFFFFF,
                                         16)) & 0xFFFFFFFF
                    Q[44] = (Q[43] + cls(((Q[43] ^ Q[42] ^ Q[41]) + Q[40] + x[6] + 0x4881d05) & 0xFFFFFFFF,
                                         23)) & 0xFFFFFFFF
                    Q[45] = (Q[44] + cls(((Q[44] ^ Q[43] ^ Q[42]) + Q[41] + x[9] + 0xd9d4d039) & 0xFFFFFFFF,
                                         4)) & 0xFFFFFFFF
                    Q[46] = (Q[45] + cls(((Q[45] ^ Q[44] ^ Q[43]) + Q[42] + x[12] + 0xe6db99e5) & 0xFFFFFFFF,
                                         11)) & 0xFFFFFFFF
                    Q[47] = (Q[46] + cls(((Q[46] ^ Q[45] ^ Q[44]) + Q[43] + x[15] + 0x1fa27cf8) & 0xFFFFFFFF,
                                         16)) & 0xFFFFFFFF
                    Q[48] = (Q[47] + cls(((Q[47] ^ Q[46] ^ Q[45]) + Q[44] + x[2] + 0xc4ac5665) & 0xFFFFFFFF,
                                         23)) & 0xFFFFFFFF

                    bitJ = Q[46] & longmask[32]
                    if (Q[48] & longmask[32]) != bitJ:
                        continue

                    Q[49] = (Q[48] + cls(((Q[47] ^ (Q[48] | ~Q[46])) + Q[45] + x[0] + 0xf4292244) & 0xFFFFFFFF,
                                         6)) & 0xFFFFFFFF
                    bitK = Q[47] & longmask[32]
                    if (Q[49] & longmask[32]) != bitK:
                        continue

                    Q[50] = (Q[49] + cls(((Q[48] ^ (Q[49] | ~Q[47])) + Q[46] + x[7] + 0x432aff97) & 0xFFFFFFFF,
                                         10)) & 0xFFFFFFFF
                    bit_J_neg = bitJ ^ longmask[32]
                    if (Q[50] & longmask[32]) != bit_J_neg:
                        continue

                    Q[51] = (Q[50] + cls(((Q[49] ^ (Q[50] | ~Q[48])) + Q[47] + x[14] + 0xab9423a7) & 0xFFFFFFFF,
                                         15)) & 0xFFFFFFFF
                    if (Q[51] & longmask[32]) != bitK:
                        continue
                    Q[52] = (Q[51] + cls(((Q[50] ^ (Q[51] | ~Q[49])) + Q[48] + x[5] + 0xfc93a039) & 0xFFFFFFFF,
                                         21)) & 0xFFFFFFFF
                    if (Q[52] & longmask[32]) != bit_J_neg:
                        continue
                    Q[53] = (Q[52] + cls(((Q[51] ^ (Q[52] | ~Q[50])) + Q[49] + x[12] + 0x655b59c3) & 0xFFFFFFFF,
                                         6)) & 0xFFFFFFFF
                    if (Q[53] & longmask[32]) != bitK:
                        continue
                    Q[54] = (Q[53] + cls(((Q[52] ^ (Q[53] | ~Q[51])) + Q[50] + x[3] + 0x8f0ccc92) & 0xFFFFFFFF,
                                         10)) & 0xFFFFFFFF
                    if (Q[54] & longmask[32]) != bit_J_neg:
                        continue
                    Q[55] = (Q[54] + cls(((Q[53] ^ (Q[54] | ~Q[52])) + Q[51] + x[10] + 0xffeff47d) & 0xFFFFFFFF,
                                         15)) & 0xFFFFFFFF
                    if (Q[55] & longmask[32]) != bitK:
                        continue
                    Q[56] = (Q[55] + cls(((Q[54] ^ (Q[55] | ~Q[53])) + Q[52] + x[1] + 0x85845dd1) & 0xFFFFFFFF,
                                         21)) & 0xFFFFFFFF
                    if (Q[56] & longmask[32]) != bit_J_neg:
                        continue
                    Q[57] = (Q[56] + cls(((Q[55] ^ (Q[56] | ~Q[54])) + Q[53] + x[8] + 0x6fa87e4f) & 0xFFFFFFFF,
                                         6)) & 0xFFFFFFFF
                    if (Q[57] & longmask[32]) != bitK:
                        continue
                    Q[58] = (Q[57] + cls(((Q[56] ^ (Q[57] | ~Q[55])) + Q[54] + x[15] + 0xfe2ce6e0) & 0xFFFFFFFF,
                                         10)) & 0xFFFFFFFF
                    if (Q[58] & longmask[32]) != bit_J_neg:
                        continue
                    Q[59] = (Q[58] + cls(((Q[57] ^ (Q[58] | ~Q[56])) + Q[55] + x[6] + 0xa3014314) & 0xFFFFFFFF,
                                         15)) & 0xFFFFFFFF
                    if (Q[59] & longmask[32]) != bitK:
                        continue
                    Q[60] = (Q[59] + cls(((Q[58] ^ (Q[59] | ~Q[57])) + Q[56] + x[13] + 0x4e0811a1) & 0xFFFFFFFF,
                                         21)) & 0xFFFFFFFF
                    if (Q[60] & longmask[32]) != bitJ:
                        continue
                    if (Q[60] & longmask[26]) != 0:
                        continue
                    Q[61] = (Q[60] + cls(((Q[59] ^ (Q[60] | ~Q[58])) + Q[57] + x[4] + 0xf7537e82) & 0xFFFFFFFF,
                                         6)) & 0xFFFFFFFF
                    if (Q[61] & longmask[32]) != bitK:
                        continue
                    if (Q[61] & longmask[26]) != longmask[26]:
                        continue
                    zavorka_Q62 = ((Q[60] ^ (Q[61] | ~Q[59])) + Q[58] + x[11] + 0xbd3af235) & 0xFFFFFFFF
                    if (zavorka_Q62 & 0x003f8000) == 0:
                        continue

                    Q[62] = (Q[61] + cls(zavorka_Q62, 10)) & 0xFFFFFFFF
                    if (Q[62] & longmask[32]) != bitJ:
                        continue
                    if (Q[62] & longmask[26]) != longmask[26]:
                        continue
                    Q[63] = (Q[62] + cls(((Q[61] ^ (Q[62] | ~Q[60])) + Q[59] + x[2] + 0x2ad7d2bb) & 0xFFFFFFFF,
                                         15)) & 0xFFFFFFFF
                    if (Q[63] & longmask[32]) != bitK:
                        continue
                    if (Q[63] & longmask[26]) != longmask[26]:
                        continue
                    Q[64] = (Q[63] + cls(((Q[62] ^ (Q[63] | ~Q[61])) + Q[60] + x[9] + 0xeb86d391) & 0xFFFFFFFF,
                                         21)) & 0xFFFFFFFF
                    if (Q[64] & longmask[26]) != longmask[26]:
                        continue  # not necessary (Sasaki), try to remove

                    IHV2 = [0] * 4
                    IHV2[0] = (P_IHV1[0] + Q[61]) & 0xFFFFFFFF
                    IHV2[1] = (P_IHV1[1] + Q[64]) & 0xFFFFFFFF
                    IHV2[2] = (P_IHV1[2] + Q[63]) & 0xFFFFFFFF
                    IHV2[3] = (P_IHV1[3] + Q[62]) & 0xFFFFFFFF

                    M = x.copy()

                    M[4] = (x[4] - 0x80000000) % (1 << 32)
                    M[11] = (x[11] - 0x00008000) % (1 << 32)
                    M[14] = (x[14] - 0x80000000) % (1 << 32)

                    temp = P_HIHV1.copy()
                    md5.compress(temp, M)

                    HIHV2 = temp.copy()
                    print(f"Block2: {os.getpid()}")
                    print((HIHV2[0] - IHV2[0]) % (1 << 32))
                    print((HIHV2[1] - IHV2[1]) % (1 << 32))
                    print((HIHV2[2] - IHV2[2]) % (1 << 32))
                    print((HIHV2[3] - IHV2[3]) % (1 << 32))
                    if (((HIHV2[0] - IHV2[0]) % (1 << 32) != 0) or
                            ((HIHV2[1] - IHV2[1]) % (1 << 32) != 0) or
                            ((HIHV2[2] - IHV2[2]) % (1 << 32) != 0) or
                            ((HIHV2[3] - IHV2[3]) % (1 << 32) != 0)):
                        continue

                    global x1, M1, x2, M2, Q2, hashDigest
                    # print(f"Block 1: {list(map(hex, x1))}, {list(map(hex, x))}")
                    # print(f"Block 2: {list(map(hex, M1))}, {list(map(hex, M))}")
                    md5.compress(P_IHV1, x)  # Compression of P_HIHV1 already done before ^
                    # print(f"Hash digest H: {P_IHV1}")
                    # print(f"Hash digest H': {temp}")
                    for i in range(len(P_IHV1)):
                        if P_IHV1[i] != temp[i]:
                            return -1
                    Q2 = Q.copy()
                    x2 = x.copy()
                    M2 = M.copy()
                    hashDigest = P_IHV1.copy()
                    print("SUPER DONEEEEEEEE!!!!!!!!!!")
                    return 0
    return -1


def main():
    print("The program creates 2 text files:")
    print(f"collisions_{now}.txt, containing collisions.")
    print(f"states_{now}.txt, containing the states of the used random number generator.")
    print("The program takes pseudorandom numbers and its behaviour is probabilistic.")
    print("You can restart the program from the same point using HEXnumber as a parameter.")

    # sprintf(out_filename, "collision_md5_%08X.TXT", X)
    newDir = os.path.join(os.getcwd(), "collisions")

    try:
        if not os.path.exists(newDir):
            os.makedirs(newDir)
    except OSError:
        sys.exit(f"Fatal: output directory {newDir} does not exist and cannot be created")
    filePath = os.path.join(newDir, f"collisions_{now}.txt")
    with open(filePath, "a+") as file:
        file.write(f"Starting time: {datetime.now().strftime('%d.%m.%Y-%H:%M:%S')}\n")
        file.close()

    cpuCount = int(cpu_count() * 0.9)
    seeds = [None] * cpuCount
    if len(sys.argv) > 1 and type(sys.argv[1]) is int:
        seedStep = sys.argv[1]
        seeds = [((i + 1) * seedStep) for i in range(cpuCount)]
    print(f"Starting with RNG seeds {seeds}")
    with Pool(cpuCount) as p:
        p.map(findCollision, seeds)
        p.terminate()


def findCollision(seed):
    random.seed(seed)
    while True:
        findBlock1()


if __name__ == '__main__':
    main()
