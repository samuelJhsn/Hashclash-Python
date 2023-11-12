import block1_wang
import block1_stevens_00
def find_block1(IV):
    if (IV[1] ^ IV[2]) & (1 << 31) == 0 and \
            ((IV[1] ^ IV[3]) & (1 << 31)) == 0 and \
            (IV[3] & (1 << 25)) == 0 and \
            (IV[2] & (1 << 25)) == 0 and \
            (IV[1] & (1 << 25)) == 0 and ((IV[2] ^ IV[1]) & 1) == 0:

        IV2 = [IV[0] + (1 << 31) & 0xFFFFFFFF, IV[1] + (1 << 31) + (1 << 25) & 0xFFFFFFFF,
               IV[2] + (1 << 31) + (1 << 25) & 0xFFFFFFFF, IV[3] + (1 << 31) + (1 << 25) & 0xFFFFFFFF]
        if (IV[1] & (1 << 6)) != 0 and (IV[1] & 1) != 0:
            print("S11")
        # block = find_block1_stevens_11(IV2)
        elif (IV[1] & (1 << 6)) != 0 and (IV[1] & 1) == 0:
            print("S10")
        # block = find_block1_stevens_10(IV2)
        elif (IV[1] & (1 << 6)) == 0 and (IV[1] & 1) != 0:
            print("S01")
        # block = find_block1_stevens_01(IV2)
        else:
            print("S00")
        block = block1_stevens_00.find_block1_stevens_00(IV2)

        block[4] = block[4] + 1 << 31 & 0xFFFFFFFF
        block[11] = block[11] + 1 << 15 & 0xFFFFFFFF
        block[14] = block[14] + 1 << 31 & 0xFFFFFFFF
    else:
        print("W")
        block = block1_wang.find_block1_wang(IV)
