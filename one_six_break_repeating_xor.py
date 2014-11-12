
import unittest
import codecs
from statistics import mean
import sys
import string
import random
from pprint import pprint

from one_five_repeating_key_xor import repeating_key_xor
from one_three_xor_cipher import xor_bytes_with_byte
from one_three_xor_cipher import letters
from one_three_xor_cipher import most_likely_english_strings

def byte_to_bits(byte):
    return bin(byte)[2:].rjust(8, '0')

def bytes_to_bits(bytestring):
    return ''.join(byte_to_bits(byte) for byte in bytestring)

def hamming_distance(string1, string2):
    difference = 0
    for bit1, bit2 in zip(bytes_to_bits(string1), bytes_to_bits(string2)):
        if bit1 != bit2:
            difference += 1
    return difference

def cipher_bytes_from_file(filename):
    with open(filename, 'rb') as fp:
        b64contents = fp.read()
        return codecs.decode(b64contents, 'base64')

def score_key_size(key_size, ciphertext):
    num_key_blocks_in_ciphertext = len(ciphertext) / key_size
    num_block_pairs_to_sample = min([5, int(num_key_blocks_in_ciphertext / 2)])

    if num_block_pairs_to_sample == 0:
        raise Exception("Key size is too large to repeat fully in given ciphertext")

    block_pair_distances = []
    for sample_num in range(0, num_block_pairs_to_sample):
        start = sample_num * (key_size * 2)
        middle = start + key_size
        end = middle + key_size
        distance = hamming_distance(ciphertext[start:middle], ciphertext[middle:end])
        block_pair_distances.append(distance)

    return mean(block_pair_distances) / key_size

def guess_key_size(ciphertext):
    max_key_size = min([40, int(len(ciphertext) / 2) + 1])

    if max_key_size <= 2:
        raise Exception("Not enough ciphertext to detect key size")

    sizes_and_scores = [] # [(size, score)]
    for key_size in range(2, max_key_size):
        size_and_score = (key_size, score_key_size(key_size, ciphertext))
        sizes_and_scores.append(size_and_score)
    most_likely_pairs = sorted(sizes_and_scores, key = lambda x: x[1])
    most_likely_sizes = [pair[0] for pair in most_likely_pairs]
    return most_likely_sizes

def transpose_blocks(bytestring, block_size):
    blocks = [bytestring[i:i+block_size] for i in range(0, len(bytestring), block_size)]
    transposed_blocks = [list(block) for block in zip(*blocks)]
    return transposed_blocks

def most_likely_english_utf8_bytes(possibly_english_bytestrings):
    possibly_english_strings = [codecs.decode(string, 'utf8')
            for string in possibly_english_bytestrings]
    most_likely_strings = most_likely_english_strings(possibly_english_strings)
    return (codecs.encode(s, 'utf8') for s in most_likely_strings)

def guess_key_for_transposed_block(block):
    plaintexts_and_keys = dict((xor_bytes_with_byte(block, ord(letter)), ord(letter))
        for letter in letters)
    unicode_plaintexts = [x[0] for x in plaintexts_and_keys.items()]

    possibly_english_plaintexts = most_likely_english_utf8_bytes(unicode_plaintexts)

    return (plaintexts_and_keys[s] for s in possibly_english_plaintexts)


def crack_ciphertext_for_key_size(ciphertext, key_size):
    block_samples = transpose_blocks(ciphertext, key_size)
    entire_key_guesses = [guess_key_for_transposed_block(b) for b in block_samples]
    return entire_key_guesses

class Test16BreakRepeatingXor(unittest.TestCase):

    def _english_sample_bytes(self):
        with open('resources/english_language_sample.txt', 'rb') as fp:
            return fp.read()

    def test_hamming_distance(self):
        distance = hamming_distance(b'this is a test', b'wokka wokka!!!')
        self.assertEqual(distance, 37)

    def test_score_key_size(self):
        ciphertext = b'this is a test' + b'wokka wokka!!!'\
                   + b'this is a test' + b'tokka wokka!!!'
        score = score_key_size(14, ciphertext)
        self.assertEqual(score, 36 / 14)

    def test_guess_key_size_with_dummy_ciphertext(self):
        ciphertext = b"111" + b"111" + b"222" + b"222"
        self.assertIn(3, guess_key_size(ciphertext)[:5])

    def test_guess_key_size_with_simple_ciphertext(self):
        plaintext = b"1" * 100
        ciphertext = repeating_key_xor(plaintext, b'12345')
        self.assertIn(5, guess_key_size(ciphertext)[:5])

    def test_guess_key_size_with_english_sample_ciphertext(self):
        plaintext = self._english_sample_bytes()
        key = b'akey'
        ciphertext = repeating_key_xor(plaintext, key)
        self.assertIn(len(key), guess_key_size(ciphertext)[:5])

    def test_transpose_blocks(self):
        ciphertext = b'123' * 3
        transposed_blocks = transpose_blocks(ciphertext, 3)
        self.assertEqual(transposed_blocks, [[49, 49, 49], [50, 50, 50], [51, 51, 51]])

    def test_guess_key_for_transposed_block(self):
        block = b'this is english text'
        key = ord('a')
        ciphertext = xor_bytes_with_byte(block, key)
        most_likely_key = list(guess_key_for_transposed_block(ciphertext))[0]
        self.assertEqual(most_likely_key, key)

    def test_guess_real_ciphertext_key_size(self):
        ciphertext = cipher_bytes_from_file('resources/6.txt')
        key_size_guesses = guess_key_size(ciphertext)[:5]
        possible_keys = [ key for i in key_size_guesses
                for key in crack_ciphertext_for_key_size(ciphertext, i)]
        possible_plaintexts = [repeating_key_xor(ciphertext, key) for key in possible_keys]

        print(len(possible_plaintexts))
        for text in possible_plaintexts:
            print(text[:80])
