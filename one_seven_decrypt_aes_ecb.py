
import unittest
import codecs

from Crypto.Cipher import AES
from Crypto import Random

def read_ciphertext(file_path):
    with open(file_path, 'rb') as fp:
        return codecs.decode(fp.read(), 'base64')

def decrypt_aes_128_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

class Test17DecryptAesEcb(unittest.TestCase):

    def test_get_ciphertext(self):
        cipher_bytes = read_ciphertext('resources/7.txt')
        self.assertEqual(type(cipher_bytes), bytes)

    def test_decrypt_aes_128_ecb(self):
        plaintext = b'Sixteen byte msg'
        key = b'Sixteen byte key'
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = decrypt_aes_128_ecb(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_decrypt_real_data(self):
        ciphertext = read_ciphertext('resources/7.txt')
        key = b'YELLOW SUBMARINE'
        decrypted = decrypt_aes_128_ecb(ciphertext, key)
        self.assertTrue(decrypted.startswith(b"I'm back and I'm ringin' the bell"))
