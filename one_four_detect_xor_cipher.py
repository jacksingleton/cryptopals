
import unittest
import codecs
from pprint import pprint

import one_three_xor_cipher as one_three

def cipher_lines_from_file():
    with open('resources/4.txt', 'r') as fp:
        return (line.rstrip('\n') for line in fp.readlines())


#class Test14DetectXorCipher(unittest.TestCase):
#
#    def test_detect_xor_cipher(self):
#        cipher_texts = (codecs.decode(line, 'hex') for line in cipher_lines_from_file())
#        possibly_decrypted_texts = (one_three.crack_ciphertext(text) for text in cipher_texts)
#        most_likely_plaintext = one_three.most_likely_english_string(possibly_decrypted_texts)
#        print(most_likely_plaintext)
