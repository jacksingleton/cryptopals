
import unittest
import itertools
import codecs

def repeating_key_xor(plaintext_bytes, key_bytes):
    repeating_key_bytes = itertools.cycle(key_bytes)
    def xor_bytes():
        for plaintext_byte, key_byte in zip(plaintext_bytes, repeating_key_bytes):
            yield plaintext_byte ^ key_byte
    return bytes(xor_bytes())


class Test15RepeatingKeyXor(unittest.TestCase):

    def test_repeating_key_xor(self):
        plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        expected_ciphertext = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        key = b'ICE'
        actual_ciphertext = repeating_key_xor(plaintext, key)
        self.assertEqual(codecs.encode(actual_ciphertext, 'hex'), expected_ciphertext)
