#!/usr/bin/env python3

def fixed_xor_bytestring(bytes1, bytes2):
    return bytes(fixed_xor_bytes(bytes1, bytes2))

def fixed_xor_bytes(bytes1, bytes2):
    for byte1, byte2 in zip(bytes1, bytes2):
        yield byte1 ^ byte2
