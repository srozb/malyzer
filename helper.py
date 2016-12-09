# -*- coding: utf-8 -*-

import os
from winappdbg import HexDump


def hexprint(data):
    return HexDump.hexline(data)


def hexaddr(address, bits):
    return HexDump.address(address, bits)


def mkdir(path):
    try:
        os.mkdir(path)
    except:
        pass