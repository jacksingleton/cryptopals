
import unittest
import codecs

def read_ciphertexts(file_path):
    def decode(line):
        return codecs.decode(line.rstrip(b'\n'), 'hex')
    with open(file_path, 'rb') as fp:
        return [decode(line) for line in fp.readlines()]

class Test18DetectAesEcb(unittest.TestCase):

    def test_read_ciphertexts(self):
        ciphertexts = read_ciphertexts('resources/8.txt')
        for ciphertext in ciphertexts:
            self.assertNotEqual(ciphertext[-1], ord('\n'))
            self.assertEqual(type(ciphertext), bytes)

#    def test_detect_ecb_can_distinguish_from_random(self):
#        random = 'fswbWIzkRayjL8vI6Zl6Ozz7yZKj/hAzAuOx+z/0blpv+UFG8cfg9w'


