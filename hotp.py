#!/usr/bin/python3
# -*- coding: utf-8 -*-
from __future__ import division, print_function, unicode_literals
import hmac
import hashlib


def int_to_8bytes(x):
    b = [0]*8
    for i in range(8):
        b[7-i] = x % 256
        x = x // 256
    return bytes(b)


def calculate_HOTP(key, counter, digits=6):
    hasher = hmac.new(key, int_to_8bytes(counter), hashlib.sha1)
    hash_value = hasher.digest()
    offset = hash_value[19] & 15
    bin_code = (hash_value[offset] & 0x7f) << 24 | (hash_value[offset + 1] & 0xff) << 16 | \
               (hash_value[offset + 2] & 0xff) << 8 | (hash_value[offset + 3] & 0xff)
    format_str = "{:0>"+str(digits)+"d}"
    return format_str.format(bin_code % 10**digits)


if __name__ == "__main__":
    key = bytearray.fromhex('c4337ed5bcbbb10d4cef4f4a43aa263fb85b0a2b')
    for counter in range(20):
        print(calculate_HOTP(key, counter))
