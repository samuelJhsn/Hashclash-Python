import random

import md5

seed32_1 = 0x12
seed32_2 = 0x12345678


def xrng64():
    global seed32_1
    global seed32_2
    t = (seed32_1 ^ (seed32_1 << 10)) & 0xFFFFFFFF
    seed32_1 = seed32_2
    seed32_2 = ((seed32_2 ^ (seed32_2 >> 10)) ^ (t ^ (t >> 13))) & 0xFFFFFFFF
    return seed32_1


def find_block0(IV):
    block = [0] * 16
    Q = [IV[0], IV[3], IV[2], IV[1]] + [0] * 64

    q4mask = [0] * 16
    q4mask = [(((k << 2) ^ (k << 26)) & 0x38000004) for k in range(len(q4mask))]

    q9q10mask = [0] * 8
    q9q10mask = [(((k << 13) ^ (k << 4)) & 0x2060) for k in range(len(q9q10mask))]

    q9mask = [0] * 65536
    q9mask = [(((k << 1) ^ (k << 2) ^ (k << 5) ^ (k << 7) ^ (k << 8) ^ (k << 10) ^ (k << 11) ^ (k << 13)) & 0x0eb94f16)
              for k in range(len(q9mask))]

    while True:

        Q[4] = random.randint(0, (2 ** 32) - 1)
        Q[6] = (random.randint(0, (2 ** 32) - 1) & 0xfe87bc3f) | 0x017841c0
        Q[7] = (random.randint(0, (2 ** 32) - 1) & 0x44000033) | 0x000002c0 | (Q[6] & 0x0287bc00)
        Q[8] = 0x41ffffc8 | (Q[7] & 0x04000033)
        Q[9] = 0xb84b82d6
        Q[10] = (random.randint(0, (2 ** 32) - 1) & 0x68000084) | 0x02401b43
        Q[11] = (random.randint(0, (2 ** 32) - 1) & 0x2b8f6e04) | 0x005090d3 | (~Q[10] & 0x40000000)
        Q[12] = 0x20040068 | (Q[11] & 0x00020000) | (~Q[11] & 0x40000000)
        Q[13] = (random.randint(0, (2 ** 32) - 1) & 0x40000000) | 0x1040b089
        Q[14] = (random.randint(0, (2 ** 32) - 1) & 0x10408008) | 0x0fbb7f16 | (~Q[13] & 0x40000000)
        Q[15] = (random.randint(0, (2 ** 32) - 1) & 0x1ed9df7f) | 0x00022080 | (~Q[14] & 0x40200000)
        Q[16] = (random.randint(0, (2 ** 32) - 1) & 0x5efb4f77) | 0x20049008
        Q[17] = (random.randint(0, (2 ** 32) - 1) & 0x1fff5f77) | 0x0000a088 | (~Q[16] & 0x40000000)
        Q[18] = (random.randint(0, (2 ** 32) - 1) & 0x5efe7ff7) | 0x80008000 | (~Q[17] & 0x00010000)
        Q[19] = (random.randint(0, (2 ** 32) - 1) & 0x1ffdffff) | 0xa0000000 | (~Q[18] & 0x40020000)

        block[0] = md5.md5_reverse_step(0, Q, 0xd76aa478, 7)
        block[6] = md5.md5_reverse_step(6, Q, 0xa8304613, 17)
        block[7] = md5.md5_reverse_step(7, Q, 0xfd469501, 22)
        block[11] = md5.md5_reverse_step(11, Q, 0x895cd7be, 22)
        block[14] = md5.md5_reverse_step(14, Q, 0xa679438e, 17)
        block[15] = md5.md5_reverse_step(15, Q, 0x49b40821, 22)

        tt1 = (md5.F(Q[4], Q[3], Q[2]) + Q[1] + 0xe8c7b756) & 0xFFFFFFFF
        tt17 = (md5.G(Q[19], Q[18], Q[17]) + Q[16] + 0xf61e2562) & 0xFFFFFFFF
        tt18 = (Q[17] + 0xc040b340 + block[6]) & 0xFFFFFFFF
        tt19 = (Q[18] + 0x265e5a51 + block[11]) & 0xFFFFFFFF
        tt20 = (Q[19] + 0xe9b6c7aa + block[0]) & 0xFFFFFFFF
        tt5 = (md5.crs((Q[9] - Q[8]) % (1 << 32), 12) - md5.F(Q[8], Q[7], Q[6]) - 0x4787c62a) % (1 << 32)

        counter = 0
        while counter < (1 << 7):

            q16 = Q[19]

            q17 = ((random.randint(0, (2 ** 32) - 1) & 0x3ffd7ff7) | (q16 & 0xc0008008)) ^ 0x40000000
            counter += 1

            q18 = (md5.G(q17, q16, Q[18]) + tt18) & 0xFFFFFFFF
            q18 = (md5.cls(q18, 9) + q17) & 0xFFFFFFFF
            if 0x00020000 != ((q18 ^ q17) & 0xa0020000):
                continue

            q19 = (md5.G(q18, q17, q16) + tt19) & 0xFFFFFFFF
            q19 = (md5.cls(q19, 14) + q18) & 0xFFFFFFFF
            if 0x80000000 != (q19 & 0x80020000):
                continue

            q20 = (md5.G(q19, q18, q17) + tt20) & 0xFFFFFFFF
            q20 = (md5.cls(q20, 20) + q19) & 0xFFFFFFFF
            if 0x00040000 != ((q20 ^ q19) & 0x80040000):
                continue

            block[1] = (q17 - q16) % (1 << 32)
            block[1] = (md5.crs(block[1], 5) - tt17) % (1 << 32)

            q2 = (block[1] + tt1) & 0xFFFFFFFF
            q2 = (md5.cls(q2, 12) + Q[4]) & 0xFFFFFFFF
            block[5] = (tt5 - q2) % (1 << 32)

            Q[5] = q2
            Q[20] = q17
            Q[21] = q18
            Q[22] = q19
            Q[23] = q20
            block[2] = md5.md5_reverse_step(2, Q, 0x242070db, 17)

            counter = 0
            break

        if counter != 0:
            continue

        q4 = Q[7]
        q9backup = Q[12]
        tt21 = (md5.G(Q[23], Q[22], Q[21]) + Q[20] + 0xd62f105d) & 0xFFFFFFFF

        # iterate over possible changes of q4
        # while keeping all conditions on q1-q20 intact
        # this changes m3, m4, m5 and m7

        for counter2 in range(1 << 4):

            Q[7] = q4 ^ q4mask[counter2]
            block[5] = md5.md5_reverse_step(5, Q, 0x4787c62a, 12)

            q21 = (tt21 + block[5]) & 0xFFFFFFFF
            q21 = (md5.cls(q21, 5) + Q[23]) & 0xFFFFFFFF

            if 0 != ((q21 ^ Q[23]) & 0x80020000):
                continue

            Q[24] = q21
            block[3] = md5.md5_reverse_step(3, Q, 0xc1bdceee, 22)
            block[4] = md5.md5_reverse_step(4, Q, 0xf57c0faf, 7)
            block[7] = md5.md5_reverse_step(7, Q, 0xfd469501, 22)

            tt22 = (md5.G(Q[24], Q[23], Q[22]) + Q[21] + 0x02441453) & 0xFFFFFFFF
            tt23 = (Q[22] + 0xd8a1e681 + block[15]) & 0xFFFFFFFF
            tt24 = (Q[23] + 0xe7d3fbc8 + block[4]) & 0xFFFFFFFF

            tt9 = (Q[9] + 0x8b44f7af) & 0xFFFFFFFF
            tt10 = (Q[10] + 0xffff5bb1) & 0xFFFFFFFF
            tt8 = (md5.F(Q[11], Q[10], Q[9]) + Q[8] + 0x698098d8) & 0xFFFFFFFF
            tt12 = (md5.crs((Q[16] - Q[15]) % (1 << 32), 7) - 0x6b901122) % (1 << 32)
            tt13 = (md5.crs((Q[17] - Q[16]) % (1 << 32), 12) - md5.F(Q[16], Q[15], Q[14]) - 0xfd987193) % (1 << 32)

            # iterate over possible changes of q9 and q10
            # while keeping conditions on q1-q21 intact
            # this changes m8, m9, m10, m12 and m13( and not m11!)
            # the possible changes of q9 that also do not change m10 are used below

            for counter3 in range(1 << 3):

                q10 = Q[13] ^ (q9q10mask[counter3] & 0x60)
                Q[12] = q9backup ^ (q9q10mask[counter3] & 0x2000)

                m10 = md5.crs((Q[14] - q10) % (1 << 32), 17)
                m10 = (m10 - md5.F(q10, Q[12], Q[11]) - tt10) % (1 << 32)

                aa = Q[24]

                dd = (tt22 + m10) & 0xFFFFFFFF
                dd = (md5.cls(dd, 9) + aa) & 0xFFFFFFFF

                if 0x80000000 != (dd & 0x80000000):
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
                block[13] = (tt13 - q10) % (1 << 32)

                # iterate over possible changes of q9 and q10
                # while keeping conditions on q1-q21 intact
                # this changes m8, m9, m10, m12 and m13( and not m11!)
                # the possible changes of q9 that also do not change m10 are used below
                for counter4 in range(1 << 16):

                    q9 = Q[12] ^ q9mask[counter4]
                    block[12] = (tt12 - md5.F(Q[15], Q[14], q10) - q9) % (1 << 32)

                    m8 = (q9 - Q[11]) % (1 << 32)
                    block[8] = (md5.crs(m8, 7) - tt8) % (1 << 32)

                    m9 = (q10 - q9) % (1 << 32)
                    block[9] = (md5.crs(m9, 12) - md5.F(q9, Q[11], Q[10]) - tt9) % (1 << 32)

                    a = aa
                    b = bb
                    c = cc
                    d = dd

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
                    b = md5.md5_step(md5.I, b, c, d, a, block[9], 0xeb86d391, 21)

                    IHV1 = (b + IV[1]) & 0xFFFFFFFF
                    IHV2 = (c + IV[2]) & 0xFFFFFFFF
                    IHV3 = (d + IV[3]) & 0xFFFFFFFF

                    wang = True
                    if 0x02000000 != ((IHV2 ^ IHV1) & 0x86000000):
                        wang = False
                    if 0 != ((IHV1 ^ IHV3) & 0x82000000):
                        wang = False
                    if 0 != (IHV1 & 0x06000020):
                        wang = False

                    stevens = True
                    if (
                            ((IHV1 ^ IHV2) >> 31) != 0 or
                            ((IHV1 ^ IHV3) >> 31) != 0):
                        stevens = False
                    if (
                            (IHV3 & (1 << 25)) != 0 or
                            (IHV2 & (1 << 25)) != 0 or
                            (IHV1 & (1 << 25)) != 0 or
                            ((IHV2 ^ IHV1) & 1) != 0):
                        stevens = False

                    print(".0", end="")

                    if not (wang or stevens):
                        continue

                    IV1 = IV.copy()
                    IV2 = IV.copy()
                    block2 = block.copy()

                    block2[4] = (block2[4] + (1 << 31)) & 0xFFFFFFFF
                    block2[11] = (block2[11] + (1 << 15)) & 0xFFFFFFFF
                    block2[14] = (block2[14] + (1 << 31)) & 0xFFFFFFFF

                    IV1 = md5.compress(IV1, block)
                    IV2 = md5.compress(IV2, block2)

                    #print(f"{IV2[0] == ((IV1[0] + (1 << 31)) & 0xFFFFFFFF)}, "
                    #      f"{(IV2[1] == ((IV1[1] + (1 << 31) + (1 << 25)) & 0xFFFFFFFF))}, "
                    #      f"{(IV2[2] == (IV1[2] + (1 << 31) + (1 << 25) & 0xFFFFFFFF))}, "
                    #      f"{IV2[3] == (IV1[3] + (1 << 31) + (1 << 25) & 0xFFFFFFFF)}")

                    if (IV2[0] == ((IV1[0] + (1 << 31)) & 0xFFFFFFFF)) and \
                            (IV2[1] == ((IV1[1] + (1 << 31) + (1 << 25)) & 0xFFFFFFFF)) and \
                            (IV2[2] == ((IV1[2] + (1 << 31) + (1 << 25)) & 0xFFFFFFFF)) and \
                            (IV2[3] == ((IV1[3] + (1 << 31) + (1 << 25)) & 0xFFFFFFFF)):
                        print(f"\nFound block: {block}")
                        return block

                    if IV2[0] != ((IV1[0] + (1 << 31)) & 0xFFFFFFFF):
                        print("!", end="")
