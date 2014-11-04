#!/usr/bin/env python3

import unittest
import codecs

from one_two_fixed_xor import *

class Test12FixedXor(unittest.TestCase):

    def test_fixed_xor_bytes(self):
        bytes1 = codecs.decode('1c0111001f010100061a024b53535009181c', 'hex')
        bytes2 = codecs.decode('686974207468652062756c6c277320657965', 'hex')
        xor_bytes = codecs.decode('746865206b696420646f6e277420706c6179', 'hex')
        self.assertEqual(fixed_xor_bytestring(bytes1, bytes2), xor_bytes)
