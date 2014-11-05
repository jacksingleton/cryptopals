
import unittest
import itertools
import codecs

def repeating_key_xor(plaintext, key):
    plaintext_bytes = bytes(plaintext, 'utf-8')
    key_bytes = itertools.cycle(bytes(key, 'utf-8'))
    def xor_bytes():
        for plaintext_byte, key_byte in zip(plaintext_bytes, key_bytes):
            yield plaintext_byte ^ key_byte
    encoded = codecs.encode(bytes(xor_bytes()), 'hex')
    return encoded


class Test15RepeatingKeyXor(unittest.TestCase):

    def test_repeating_key_xor(self):
        plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        expected_ciphertext = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        key = 'ICE'
        actual_ciphertext = repeating_key_xor(plaintext, key)
        self.assertEqual(actual_ciphertext, expected_ciphertext)
