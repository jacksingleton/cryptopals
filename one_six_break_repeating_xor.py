
import unittest
import codecs
from statistics import mean
import sys
import string
import random
from pprint import pprint
import itertools

from one_five_repeating_key_xor import repeating_key_xor
from one_three_xor_cipher import xor_bytes_with_byte
from one_three_xor_cipher import letters
from one_three_xor_cipher import most_likely_english_strings
from one_three_xor_cipher import english_language_score

def percent(fraction):
    return (fraction.numerator / fraction.denominator) * 100

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

def transpose(list_of_lists):
    return [list(t) for t in zip(*list_of_lists)]

def transpose_blocks(bytestring, block_size):
    block_remainder_characters = len(bytestring) % block_size
    even_block_bytestring = bytestring[:-block_remainder_characters]
    blocks = [even_block_bytestring[i:i+block_size]
            for i in range(0, len(even_block_bytestring), block_size)]
    return transpose(blocks)

def guess_key_for_transposed_block(block):
    def keys_and_scores():
        for letter in letters:
            letter_byte = ord(letter)
            plaintext_bytes = xor_bytes_with_byte(block, letter_byte)
            plaintext_unicode = codecs.decode(plaintext_bytes, 'utf8', 'ignore')
            yield (letter_byte, english_language_score(plaintext_unicode))

    sorted_keys_and_scores = sorted(keys_and_scores(), key = lambda ks: ks[1])

    most_likely_keys = [ks[0] for ks in sorted_keys_and_scores]

    return most_likely_keys

def crack_ciphertext_for_key_size(ciphertext, key_size):
    block_samples = transpose_blocks(ciphertext, key_size)
    block_sample_guesses = [guess_key_for_transposed_block(b) for b in block_samples]
    entire_key_guesses = [bytes(k) for k in transpose(block_sample_guesses)]
    return entire_key_guesses

def crack_ciphertext(ciphertext):
    key_size_guesses = guess_key_size(ciphertext)[:5]
    key_guesses = [key
            for key_size in key_size_guesses
            for key in crack_ciphertext_for_key_size(ciphertext, key_size)[:5]]

    def score_key_and_text():
        for key in key_guesses:
            maybe_plaintext = repeating_key_xor(ciphertext, key)
            plaintext_unicode = codecs.decode(maybe_plaintext, 'utf8', 'ignore')
            plaintext_score = english_language_score(plaintext_unicode)
            yield (plaintext_score, key, maybe_plaintext)

    return sorted(score_key_and_text(), key = lambda skt: skt[0])


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

    def test_guess_key_size_with_english_sample_plaintext(self):
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

    def test_transpose_blocks(self):
        bytestring = bytes([ 1,  2,  3,
                             4,  5,  6,
                             7,  8,  9,
                            10, 11, 12,
                            13, 14, 15,
                            16])
        block_size = 3
        transposed = transpose_blocks(bytestring, block_size)
        self.assertEqual(transposed,
                [[ 1,  4,  7, 10, 13],
                 [ 2,  5,  8, 11, 14],
                 [ 3,  6,  9, 12, 15]])

#    # Takes a while
#    def test_crack_english_sample_plaintext(self):
#        plaintext = self._english_sample_bytes()
#        key = b'akey'
#        ciphertext = repeating_key_xor(plaintext, key)
#        possible_plaintexts = [text for _, _, text in crack_ciphertext(ciphertext)]
#        self.assertIn(plaintext, possible_plaintexts)

#    # Takes a while
#    def test_guess_real_ciphertext_key_size(self):
#        ciphertext = cipher_bytes_from_file('resources/6.txt')
#        score, key, plaintext = crack_ciphertext(ciphertext)[0]
#        self.assertEqual(codecs.decode(key, 'utf8'), 'Terminator X: Bring the noise')
