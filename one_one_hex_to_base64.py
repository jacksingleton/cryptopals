#!/usr/bin/env python3

import base64
import codecs
import sys

def hex_string_to_base64_bytes(hex_bytes):
    ascii_bytes = codecs.decode(hex_bytes, 'hex')
    base64_bytes = codecs.encode(ascii_bytes, 'base64')
    base64_bytes_without_newline = base64_bytes[:-1]
    return base64_bytes_without_newline

if __name__ == '__main__':
    hex_string = sys.argv[1]
    base64_bytes = hex_string_to_base64_bytes(hex_string)
    print(codecs.decode(base64_bytes, 'utf-8'))
