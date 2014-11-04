#!/usr/bin/env python3

import unittest

from one_one_hex_to_base64 import *

class Test11HexToBase64(unittest.TestCase):
    def test_hex_string_to_base64_bytes(self):
        hex_bytes = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        base64_bytes = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        self.assertEqual(hex_string_to_base64_bytes(hex_bytes), base64_bytes)
