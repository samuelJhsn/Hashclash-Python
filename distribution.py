import hashlib
import os
import time
import re
import numpy as np
import sys
from multiprocessing import Pool, cpu_count
import math
import textwrap
from operator import add


def doHashing(compRoomStart, compRoomEnd, hashFunction):
    startGenBits = time.perf_counter()
    bitStrings = [e.to_bytes(math.ceil(e.bit_length() / 8), byteorder='big') for e in range(compRoomStart, compRoomEnd)]
    endGenBits = time.perf_counter()

    startHashing = time.perf_counter()
    hashes = [hashFunction(bitString).hexdigest() for bitString in bitStrings]
    endHashing = time.perf_counter()
    # hashes = [re.findall(r'.{1,2}', h, re.DOTALL) for h in hashes]
    # bitDistribution = [[0 for _ in range(hashFunction().digest_size)] for _ in range(2 ** 8)]
    # for hash in hashes:
    #     for index, byte in enumerate(hash):
    #         bitDistribution[int(byte, 16)][index] += 1

    bitDistribution = [0 for _ in range(8 * hashFunction().digest_size + 1)]
    hashes = [list(f'{int(h, 16):0>{8 * hashFunction().digest_size}b}') for h in hashes]
    hashes = [[int(numba) for numba in h] for h in hashes]
    # print(hashes[0])
    startBitCount = time.perf_counter()
    for h in hashes:
        bitDistribution = list(map(add, bitDistribution, h))

    # h = f'{int(h, 16):0>42b}'
    # h = [int(x) for x in textwrap.wrap(h, 1)]
    # bitDistribution = list(map(add, h, bitDistribution))
    # hash = bin(int(hash, 16))[2:]
    # for index, bit in enumerate(h):
    #     bitDistribution[index] += int(bit)

    endBitCount = time.perf_counter()

    # np.set_printoptions(threshold=sys.maxsize)
    # print(np.matrix(bitDistribution))

    print(
        f'''Took {endGenBits - startGenBits} seconds to generate {len(bitStrings)} Bitstrings.
Took {endHashing - startHashing} seconds to generate {len(hashes)} hashes.
Took {endBitCount - startBitCount} seconds to count {8 * hashlib.md5().digest_size * len(hashes)} bits in all hashes.
Took {endGenBits - startGenBits + endHashing - startHashing + endBitCount - startBitCount} seconds for everything.
Process {os.getpid()} has finished.
        '''
    )
    return bitDistribution


# warnings.filterwarnings("ignore")
# @jit(target_backend='cuda', nopython=False)
def main():
    try:
        if sys.argv[1].lower() not in hashlib.algorithms_guaranteed:
            print(f"Try again with a valid hash function out of: {hashlib.algorithms_guaranteed}")
            sys.exit(1)
        match sys.argv[1]:
            case "md5":
                hashFunction = hashlib.md5
            case "sha1":
                hashFunction = hashlib.sha1
            case "sha224":
                hashFunction = hashlib.sha224
            case "sha256":
                hashFunction = hashlib.sha256
            case "sha384":
                hashFunction = hashlib.sha384
            case "sha512":
                hashFunction = hashlib.sha512
            case "shake_128":
                hashFunction = hashlib.shake_128
            case "shake_256":
                hashFunction = hashlib.shake_256
            case "blake2b":
                hashFunction = hashlib.blake2b
            case "blake2s":
                hashFunction = hashlib.md5
            case "sha3_224":
                hashFunction = hashlib.sha3_224
            case "sha3_256":
                hashFunction = hashlib.sha3_256
            case "sha3_384":
                hashFunction = hashlib.sha3_384
            case _:
                hashFunction = hashlib.sha3_512
    except IndexError as indErr:
        print(f"{indErr}: Expected first argument out of: {hashlib.algorithms_guaranteed}")
        sys.exit(1)
    try:
        compRooms = getCompRooms(int(sys.argv[2]))
    except ValueError as valErr:
        print(f"{valErr}: Expected int, found {type(sys.argv[2])}")
        sys.exit(1)
    except IndexError as indErr:
        print(f"{indErr}: Expected second argument")
        sys.exit(1)
    start = time.perf_counter()
    with Pool(cpu_count() - 1) as p:
        compRooms = [tup + (hashFunction,) for tup in compRooms]
        print(
            f"Generating {compRooms[0][1]} {sys.argv[1]} hashes in each of {cpu_count() - 1} processes, please wait...")
        distributions = p.starmap(doHashing, compRooms)
    result = [sum(x) for x in zip(*distributions)]
    end = time.perf_counter()
    print(f"Took {end - start} seconds for {2 ** int(sys.argv[2])} values")
    np.savetxt("distribution.csv",
               result,
               delimiter=", ",
               fmt="% s")


def getCompRooms(minPower=0, maxPower=10):
    if minPower >= maxPower:
        minPower, maxPower = maxPower, minPower
    hashesPerProcess = int(((2 ** maxPower) - (2 ** minPower)) / cpu_count() - 1)
    return [(hashesPerProcess * i, hashesPerProcess * (i + 1)) for i in range(cpu_count() - 1)]


if __name__ == '__main__':
    main()
