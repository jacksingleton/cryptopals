
import unittest
import codecs
from pprint import pprint

import one_three_xor_cipher as one_three

def cipher_lines_from_file(filename):
    def decode_file_line(line):
        return codecs.decode(line.rstrip('\n'), 'hex')
    with open(filename, 'r') as fp:
        return (decode_file_line(line) for line in fp.readlines())

def detect_and_crack_xor_cipher(cipher_texts):
    possibly_decrypted_texts = (one_three.crack_ciphertext(text) for text in cipher_texts)
    most_likely_plaintext = one_three.most_likely_english_string(possibly_decrypted_texts)
    return most_likely_plaintext

## Takes 5 minutes :( (parallel collections for python could help?)
#class Test14DetectXorCipher(unittest.TestCase):
#
#    def test_detect_xor_cipher(self):
#        cipher_texts = cipher_lines_from_file('resources/4.txt')
#        most_likely_plaintext = detect_and_crack_xor_cipher(cipher_texts)
#        self.assertEqual(most_likely_plaintext, "Now that the party is jumping\n")
