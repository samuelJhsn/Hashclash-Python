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

import block1_wang
import block1_stevens_00
import block1_stevens_01
import block1_stevens_10
import block1_stevens_11


def find_block1(IV):
    # Check conditions on IHV for one of Stevens blocks
    if (
            ((IV[1] ^ IV[2]) & (1 << 31)) == 0 and
            ((IV[1] ^ IV[3]) & (1 << 31)) == 0 and
            (IV[3] & (1 << 25)) == 0 and
            (IV[2] & (1 << 25)) == 0 and
            (IV[1] & (1 << 25)) == 0 and ((IV[2] ^ IV[1]) & 1) == 0
    ):
        IV2 = [IV[0] + (1 << 31) & 0xFFFFFFFF, IV[1] + (1 << 31) + (1 << 25) & 0xFFFFFFFF,
               IV[2] + (1 << 31) + (1 << 25) & 0xFFFFFFFF, IV[3] + (1 << 31) + (1 << 25) & 0xFFFFFFFF]
        if (IV[1] & (1 << 6)) != 0 and (IV[1] & 1) != 0:
            block = block1_stevens_11.find_block1_stevens_11(IV2)
        elif (IV[1] & (1 << 6)) != 0 and (IV[1] & 1) == 0:
            block = block1_stevens_10.find_block1_stevens_10(IV2)
        elif (IV[1] & (1 << 6)) == 0 and (IV[1] & 1) != 0:
            block = block1_stevens_01.find_block1_stevens_01(IV2)
        else:
            block = block1_stevens_00.find_block1_stevens_00(IV2)

        block[0][4] = (block[0][4] + (1 << 31)) & 0xFFFFFFFF
        block[0][11] = (block[0][11] + (1 << 15)) & 0xFFFFFFFF
        block[0][14] = (block[0][14] + (1 << 31)) & 0xFFFFFFFF
    else:
        block = block1_wang.find_block1_wang(IV)
    return block
