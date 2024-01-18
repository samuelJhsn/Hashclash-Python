"""

MD5 collision generator
=======================
Source code files:
  block0.cpp
  block1.cpp
  main.cpp
  main.hpp
  md5.cpp
  block1wang.cpp
  block1stevens00.cpp
  block1stevens01.cpp
  block1stevens10.cpp
  block1stevens11.cpp
Win32 executable:
  fastcoll_v1.0.0.5.exe

Version
=======
version 1.0.0.5-1, April 2006.

Copyright
=========
© M. Stevens, 2006. All rights reserved.

Disclaimer
==========
This software is provided as is. Use is at the user's risk.
No guarantee whatsoever is given on how it may function or malfunction.
Support cannot be expected.
This software is meant for scientific and educational purposes only.
It is forbidden to use it for other than scientific or educational purposes.
In particular, commercial and malicious use is not allowed.
Further distribution of this software, by whatever means, is not allowed
without our consent.
This includes publication of source code or executables in printed form,
on websites, newsgroups, CD-ROM's, etc.
Changing the (source) code without our consent is not allowed.
In all versions of the source code this disclaimer, the copyright
notice and the version number should be present.

"""

import random

import md5


def find_block1_stevens_10(IV):
    block = [0] * 16
    Q = [IV[0], IV[3], IV[2], IV[1]] + [0] * 64

    q9q10mask = [0] * 16
    q9q10mask = [(((k << 2) ^ (k << 8) ^ (k << 11) ^ (k << 25)) & 0x08004204) for k in range(len(q9q10mask))]

    q9mask = [0] * 1024
    q9mask = [(((k << 1) ^ (k << 2) ^ (k << 3) ^ (k << 7) ^ (k << 12) ^ (k << 15) ^ (k << 18) ^ (k << 20)) & 0x2471042a)
              for k in range(len(q9mask))]

    while True:

        aa = Q[3] & 0x80000000

        Q[5] = (random.randrange(0, (2 ** 32)) & 0x79b0c6ba) | 0x024c3841 | aa
        Q[6] = (random.randrange(0, (2 ** 32)) & 0x19300210) | 0x2603096d | (Q[5] & 0x80000082)
        Q[7] = (random.randrange(0, (2 ** 32)) & 0x10300000) | 0xe4cae30c | (Q[6] & 0x01000030)
        Q[8] = (random.randrange(0, (2 ** 32)) & 0x10000000) | 0x63494061 | (Q[7] & 0x00300000)
        Q[9] = 0x7deaff68
        Q[10] = (random.randrange(0, (2 ** 32)) & 0x20444000) | 0x09091ee0
        Q[11] = (random.randrange(0, (2 ** 32)) & 0x09040000) | 0xb2529f6d
        Q[12] = (random.randrange(0, (2 ** 32)) & 0x00040000) | 0x10885184
        Q[13] = (random.randrange(0, (2 ** 32)) & 0x00000080) | 0x428afb11 | (Q[12] & 0x00040000)
        Q[14] = (random.randrange(0, (2 ** 32)) & 0x128a8110) | 0x6571266b | (Q[13] & 0x0000080)
        Q[15] = (random.randrange(0, (2 ** 32)) & 0x3ef38d7f) | 0x00003080 | (~Q[14] & 0x00080000)
        Q[16] = (random.randrange(0, (2 ** 32)) & 0x3efb1d77) | 0x0004c008
        Q[17] = (random.randrange(0, (2 ** 32)) & 0x5fff5d77) | 0x8000a288
        Q[18] = (random.randrange(0, (2 ** 32)) & 0x1efe7ff7) | 0xe0008000 | (~Q[17] & 0x00010000)
        Q[19] = (random.randrange(0, (2 ** 32)) & 0x5ffdffff) | 0x20000000 | (~Q[18] & 0x00020000)

        block[5] = md5.md5_reverse_step(5, Q, 0x4787c62a, 12)
        block[6] = md5.md5_reverse_step(6, Q, 0xa8304613, 17)
        block[7] = md5.md5_reverse_step(7, Q, 0xfd469501, 22)
        block[11] = md5.md5_reverse_step(11, Q, 0x895cd7be, 22)
        block[14] = md5.md5_reverse_step(14, Q, 0xa679438e, 17)
        block[15] = md5.md5_reverse_step(15, Q, 0x49b40821, 22)

        tt17 = (md5.G(Q[19], Q[18], Q[17]) + Q[16] + 0xf61e2562) & 0xFFFFFFFF

        tt18 = (Q[17] + 0xc040b340 + block[6]) & 0xFFFFFFFF

        tt19 = (Q[18] + 0x265e5a51 + block[11]) & 0xFFFFFFFF

        tt0 = (md5.F(Q[3], Q[2], Q[1]) + Q[0] + 0xd76aa478) & 0xFFFFFFFF

        tt1 = (Q[1] + 0xe8c7b756) & 0xFFFFFFFF

        q1a = 0x02000941 ^ (Q[3] & 0x80000000)

        counter = 0
        while counter < (1 << 12):

            counter += 1

            q1 = q1a | (random.randrange(0, (2 ** 32)) & 0x7dfdf6be)

            m1 = (Q[5] - q1) % (1 << 32)
            m1 = (md5.crs(m1, 12) - md5.F(q1, Q[3], Q[2]) - tt1) % (1 << 32)

            q16 = Q[19]

            q17 = (tt17 + m1) & 0xFFFFFFFF
            q17 = (md5.cls(q17, 5) + q16) & 0xFFFFFFFF
            if 0x80000000 != ((q17 ^ q16) & 0x80008008):
                continue
            if 0 != (q17 & 0x00020000):
                continue

            q18 = (md5.G(q17, q16, Q[18]) + tt18) & 0xFFFFFFFF
            q18 = md5.cls(q18, 9)
            q18 = (q18 + q17) & 0xFFFFFFFF
            if 0x80020000 != ((q18 ^ q17) & 0xa0020000):
                continue

            q19 = (md5.G(q18, q17, q16) + tt19) & 0xFFFFFFFF
            q19 = md5.cls(q19, 14)
            q19 = (q19 + q18) & 0xFFFFFFFF
            if 0 != (q19 & 0x80020000):
                continue

            m0 = (q1 - Q[3]) % (1 << 32)
            m0 = (md5.crs(m0, 7) - tt0) % (1 << 32)

            q20 = (md5.G(q19, q18, q17) + q16 + 0xe9b6c7aa + m0) & 0xFFFFFFFF
            q20 = md5.cls(q20, 20)
            q20 = (q20 + q19) & 0xFFFFFFFF
            if 0x00040000 != ((q20 ^ q19) & 0x80040000):
                continue

            Q[4] = q1
            Q[20] = q17
            Q[21] = q18
            Q[22] = q19
            Q[23] = q20

            block[0] = m0
            block[1] = m1

            block[5] = md5.md5_reverse_step(5, Q, 0x4787c62a, 12)

            q21 = (md5.G(Q[23], Q[22], Q[21]) + Q[20] + 0xd62f105d + block[5]) & 0xFFFFFFFF
            q21 = md5.cls(q21, 5)
            q21 = (q21 + Q[23])
            if 0 != ((q21 ^ Q[23]) & 0x80020000):
                continue
            Q[24] = q21

            counter = 0
            break

        if counter != 0:
            continue

        q9b = Q[12]

        q10b = Q[13]

        block[2] = md5.md5_reverse_step(2, Q, 0x242070db, 17)
        block[3] = md5.md5_reverse_step(3, Q, 0xc1bdceee, 22)
        block[4] = md5.md5_reverse_step(4, Q, 0xf57c0faf, 7)
        block[7] = md5.md5_reverse_step(7, Q, 0xfd469501, 22)

        tt10 = (Q[10] + 0xffff5bb1) & 0xFFFFFFFF

        tt22 = (md5.G(Q[24], Q[23], Q[22]) + Q[21] + 0x02441453) & 0xFFFFFFFF
        tt23 = (Q[22] + 0xd8a1e681 + block[15]) & 0xFFFFFFFF
        tt24 = (Q[23] + 0xe7d3fbc8 + block[4]) & 0xFFFFFFFF

        for k10 in range(1 << 4):

            q10 = q10b | (q9q10mask[k10] & 0x08000004)

            m10 = (md5.crs((Q[14] - q10) % (1 << 32), 17)) % (1 << 32)

            q9 = q9b | (q9q10mask[k10] & 0x00004200)

            m10 = (m10 - md5.F(q10, q9, Q[11]) - tt10) % (1 << 32)
            aa = Q[24]

            dd = (tt22 + m10) & 0xFFFFFFFF
            dd = (md5.cls(dd, 9) + aa) & 0xFFFFFFFF
            if 0 != (dd & 0x80000000):
                continue

            bb = Q[23]

            cc = (tt23 + md5.G(dd, aa, bb)) & 0xFFFFFFFF
            if 0 != (cc & 0x20000):
                continue
            cc = (md5.cls(cc, 14) + dd) & 0xFFFFFFFF
            if 0 != (cc & 0x80000000):
                continue

            bb = (tt24 + md5.G(cc, dd, aa)) & 0xFFFFFFFF
            bb = (md5.cls(bb, 20) + cc) & 0xFFFFFFFF
            if 0 == (bb & 0x80000000):
                continue

            block[10] = m10
            Q[12] = q9
            Q[13] = q10
            block[13] = md5.md5_reverse_step(13, Q, 0xfd987193, 12)

            for k9 in range(1 << 10):

                Q[12] = q9 ^ q9mask[k9]

                a = aa
                b = bb
                c = cc
                d = dd

                block[8] = md5.md5_reverse_step(8, Q, 0x698098d8, 7)
                block[9] = md5.md5_reverse_step(9, Q, 0x8b44f7af, 12)
                block[12] = md5.md5_reverse_step(12, Q, 0x6b901122, 7)

                a = md5.md5_step(md5.G, a, b, c, d, block[9], 0x21e1cde6, 5)
                d = md5.md5_step(md5.G, d, a, b, c, block[14], 0xc33707d6, 9)
                c = md5.md5_step(md5.G, c, d, a, b, block[3], 0xf4d50d87, 14)
                b = md5.md5_step(md5.G, b, c, d, a, block[8], 0x455a14ed, 20)
                a = md5.md5_step(md5.G, a, b, c, d, block[13], 0xa9e3e905, 5)
                d = md5.md5_step(md5.G, d, a, b, c, block[2], 0xfcefa3f8, 9)
                c = md5.md5_step(md5.G, c, d, a, b, block[7], 0x676f02d9, 14)
                b = md5.md5_step(md5.G, b, c, d, a, block[12], 0x8d2a4c8a, 20)
                a = md5.md5_step(md5.H, a, b, c, d, block[5], 0xfffa3942, 4)
                d = md5.md5_step(md5.H, d, a, b, c, block[8], 0x8771f681, 11)

                c = (c + md5.H(d, a, b) + block[11] + 0x6d9d6122) & 0xFFFFFFFF
                if 0 != (c & (1 << 15)):
                    continue
                c = (((c << 16) & 0xFFFFFFFF | c >> 16) + d) & 0xFFFFFFFF

                b = md5.md5_step(md5.H, b, c, d, a, block[14], 0xfde5380c, 23)
                a = md5.md5_step(md5.H, a, b, c, d, block[1], 0xa4beea44, 4)
                d = md5.md5_step(md5.H, d, a, b, c, block[4], 0x4bdecfa9, 11)
                c = md5.md5_step(md5.H, c, d, a, b, block[7], 0xf6bb4b60, 16)
                b = md5.md5_step(md5.H, b, c, d, a, block[10], 0xbebfbc70, 23)
                a = md5.md5_step(md5.H, a, b, c, d, block[13], 0x289b7ec6, 4)
                d = md5.md5_step(md5.H, d, a, b, c, block[0], 0xeaa127fa, 11)
                c = md5.md5_step(md5.H, c, d, a, b, block[3], 0xd4ef3085, 16)
                b = md5.md5_step(md5.H, b, c, d, a, block[6], 0x04881d05, 23)
                a = md5.md5_step(md5.H, a, b, c, d, block[9], 0xd9d4d039, 4)
                d = md5.md5_step(md5.H, d, a, b, c, block[12], 0xe6db99e5, 11)
                c = md5.md5_step(md5.H, c, d, a, b, block[15], 0x1fa27cf8, 16)
                b = md5.md5_step(md5.H, b, c, d, a, block[2], 0xc4ac5665, 23)
                if 0 != ((b ^ d) & 0x80000000):
                    continue

                a = md5.md5_step(md5.I, a, b, c, d, block[0], 0xf4292244, 6)
                if 0 != ((a ^ c) >> 31):
                    continue
                d = md5.md5_step(md5.I, d, a, b, c, block[7], 0x432aff97, 10)
                if 0 == ((b ^ d) >> 31):
                    continue
                c = md5.md5_step(md5.I, c, d, a, b, block[14], 0xab9423a7, 15)
                if 0 != ((a ^ c) >> 31):
                    continue
                b = md5.md5_step(md5.I, b, c, d, a, block[5], 0xfc93a039, 21)
                if 0 != ((b ^ d) >> 31):
                    continue
                a = md5.md5_step(md5.I, a, b, c, d, block[12], 0x655b59c3, 6)
                if 0 != ((a ^ c) >> 31):
                    continue
                d = md5.md5_step(md5.I, d, a, b, c, block[3], 0x8f0ccc92, 10)
                if 0 != ((b ^ d) >> 31):
                    continue
                c = md5.md5_step(md5.I, c, d, a, b, block[10], 0xffeff47d, 15)
                if 0 != ((a ^ c) >> 31):
                    continue
                b = md5.md5_step(md5.I, b, c, d, a, block[1], 0x85845dd1, 21)
                if 0 != ((b ^ d) >> 31):
                    continue
                a = md5.md5_step(md5.I, a, b, c, d, block[8], 0x6fa87e4f, 6)
                if 0 != ((a ^ c) >> 31):
                    continue
                d = md5.md5_step(md5.I, d, a, b, c, block[15], 0xfe2ce6e0, 10)
                if 0 != ((b ^ d) >> 31):
                    continue
                c = md5.md5_step(md5.I, c, d, a, b, block[6], 0xa3014314, 15)
                if 0 != ((a ^ c) >> 31):
                    continue
                b = md5.md5_step(md5.I, b, c, d, a, block[13], 0x4e0811a1, 21)
                if 0 == ((b ^ d) >> 31):
                    continue
                a = md5.md5_step(md5.I, a, b, c, d, block[4], 0xf7537e82, 6)
                if 0 != ((a ^ c) >> 31):
                    continue
                d = md5.md5_step(md5.I, d, a, b, c, block[11], 0xbd3af235, 10)
                if 0 != ((b ^ d) >> 31):
                    continue
                c = md5.md5_step(md5.I, c, d, a, b, block[2], 0x2ad7d2bb, 15)
                if 0 != ((a ^ c) >> 31):
                    continue

                print(".S10")

                IV1 = IV.copy()
                IV2 = [0] * 4
                block2 = block.copy()

                for i in range(4):
                    IV2[i] = (IV[i] + (1 << 31)) & 0xFFFFFFFF

                IV2[1] = (IV2[1] - (1 << 25)) % (1 << 32)
                IV2[2] = (IV2[2] - (1 << 25)) % (1 << 32)
                IV2[3] = (IV2[3] - (1 << 25)) % (1 << 32)

                block2[4] = (block2[4] + (1 << 31)) & 0xFFFFFFFF
                block2[11] = (block2[11] + (1 << 15)) & 0xFFFFFFFF
                block2[14] = (block2[14] + (1 << 31)) & 0xFFFFFFFF

                IV1 = md5.compress(IV1, block)
                IV2 = md5.compress(IV2, block2)

                print(f"10: {IV2[0] == IV1[0]}, {IV2[1] == IV1[1]}, {IV2[2] == IV1[2]}, {IV2[3] == IV1[3]}")
                if IV2[0] == IV1[0] and IV2[1] == IV1[1] and IV2[2] == IV1[2] and IV2[3] == IV1[3]:
                    return [block, IV1]

                if IV2[0] != IV1[0]:
                    print("!")
