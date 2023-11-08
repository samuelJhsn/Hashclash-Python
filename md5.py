from collections import deque
import struct

INT_BITS = 32

AC = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]
RC = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
    5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
]
block_indexes = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4,
    9, 14, 3, 8, 13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
]


def preprocessing(message):
    message_length = (len(hex(message)) - 2) * 4 & 0xFFFFFFFFFFFFFFFF

    message = (message << 8) | 0x80

    zerosToAdd = 448 - message_length - 8
    if zerosToAdd < 0:
        zerosToAdd += 512

    message = (message << (zerosToAdd + 64)) | int.from_bytes(message_length.to_bytes(8, byteorder='big'), "little")

    message = hex(message)[2:]

    message = [struct.unpack("<I", struct.pack(">I", int(message[i:i + 8], 16)))[0] for i in range(0, len(message), 8)]
    print(f"LAAA {message}")
    return message


def compress(ihv, message):
    for blockN in range(0, int(len(message) / 16)):
        block = message[(blockN * 16 + 0):(blockN * 16 + 16)]
        state = deque(ihv.copy())
        for i in range(64):
            if i <= 15:
                state[0] = md5_step(F, state[0], state[1], state[2], state[3], block[block_indexes[i]], AC[i], RC[i])
                state.rotate(1)

            elif i <= 31:
                state[0] = md5_step(G, state[0], state[1], state[2], state[3], block[block_indexes[i]], AC[i], RC[i])
                state.rotate(1)
            elif i <= 47:
                state[0] = md5_step(H, state[0], state[1], state[2], state[3], block[block_indexes[i]], AC[i], RC[i])
                state.rotate(1)
            else:
                state[0] = md5_step(I, state[0], state[1], state[2], state[3], block[block_indexes[i]], AC[i], RC[i])
                state.rotate(1)
        for i, _ in enumerate(ihv):
            ihv[i] = (state[i] + ihv[i] & 0xFFFFFFFF)

    for i, _ in enumerate(ihv):
        ihv[i] = int.from_bytes(ihv[i].to_bytes(4, byteorder='big'), "little")

    return ihv


def cls(a, rc):
    a &= 0xFFFFFFFF
    return (((a << rc) & 0xFFFFFFFF) | (a >> (INT_BITS - rc))) & 0xFFFFFFFF


def crs(a, rc):
    a &= 0xFFFFFFFF
    return (a >> rc) | ((a << (INT_BITS - rc)) & 0xFFFFFFFF)


def F(b, c, d): return d ^ (b & (c ^ d))


def G(b, c, d): return c ^ (d & (b ^ c))


def H(b, c, d): return b ^ c ^ d


def I(b, c, d): return c ^ (b | ~d)


def md5_step(f, a, b, c, d, word, ac, rc):
    a = (a + f(b, c, d) + word + ac) & 0xFFFFFFFF
    a = (cls(a, rc) + b) & 0xFFFFFFFF
    return a


def md5_reverse_step(t, Q, ac, rc):
    word = (Q[3 + t + 1] - Q[3 + t]) % 0xFFFFFFFF
    word = (crs(word, rc) - F(Q[3 + t], Q[3 + t - 1], Q[3 + t - 2]) - Q[3 + t - 3] - ac) % 0xFFFFFFFF
    return word


def digest(ihv, message):
    message = preprocessing(message)
    ihv = compress(ihv, message)
    return ihv


if __name__ == "__main__":
    pass
