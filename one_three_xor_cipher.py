
import unittest
from fractions import Fraction
import codecs

SAMPLE_ENGLISH_TEXT = open('resources/english_language_sample.txt', 'r').read()

letters = [chr(ascii_code) for ascii_code in range(0, 128)]

def xor_bytes_with_byte(ciphertext, key):
    return bytes(byte ^ key for byte in ciphertext)

def letter_ratios(text):
    text_length = len(text)
    letter_ratios = {}
    for letter in letters:
        count = text.count(letter)
        letter_ratios[letter] = Fraction(count, text_length)
    return letter_ratios

def score(text):
    sample_letter_ratios = letter_ratios(SAMPLE_ENGLISH_TEXT)
    text_letter_ratios = letter_ratios(text)

    running_score = 0
    for letter, sample_ratio in sample_letter_ratios.items():
        text_ratio = text_letter_ratios[letter]
        difference = abs(sample_ratio - text_ratio)
        running_score += difference

    return running_score

def most_likely_english_string(possibly_english_strings):
    return most_likely_english_strings(possibly_english_strings)[0]

def most_likely_english_strings(possibly_english_strings):
    most_likely_english = None
    scores_and_strings = []
    for string in possibly_english_strings:
        string_score = score(string)
        scores_and_strings.append((string_score, string))
    sorted_scores_and_strings = sorted(scores_and_strings, key = lambda x: x[0])
    return [score_and_string[1] for score_and_string in sorted_scores_and_strings]

def crack_ciphertext(ciphertext):
    def possible_plaintexts():
        for key in letters:
            possible_decrypted_bytes = xor_bytes_with_byte(ciphertext, ord(key))
            possible_plaintext = codecs.decode(possible_decrypted_bytes, 'ascii', 'ignore')
            yield possible_plaintext
    return most_likely_english_string(possible_plaintexts())

class Test13XorCipher(unittest.TestCase):

    def test_xor_bytes_with_byte(self):
        key = ord('a')
        plaintext = b"blah"
        ciphertext = xor_bytes_with_byte(plaintext, key)
        self.assertEqual(xor_bytes_with_byte(ciphertext, key), plaintext)

    def test_score_plaintext(self):
        random = 'wNLr3eLZpolOJcxCPxyDAPNw9YrPvKHCbX'
        english = 'this a real sentence'
        self.assertLess(score(english), score(random))

    def test_crack_ciphertext(self):
        ciphertext = codecs.decode('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 'hex')
        cracked = crack_ciphertext(ciphertext)
        self.assertEqual(cracked, "Cooking MC's like a pound of bacon")

