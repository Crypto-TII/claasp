"""
@author: trident-10 (hassan_javaid)

Text parsing file.

This implementation is the property of the author. All rights reserved.
"""
# import numpy as np
from collections import Counter


def read_book(filename):
    with open(filename, "r", encoding="utf8") as current_file:
        text = current_file.read()
        #text = text.replace("\n", "").replace("\r", "")
    return text


def count_words_fast(text):
    """
    Count the number of words in the text(str) and return a dictionary
    of word counter with {word:count} pairing. Skips punctuation.
    """
    text = text.lower().strip().splitlines()
    text = ' '.join(text)
    #   own code
    # text = text.translate(str.maketrans('','',string.punctuation))
    words = Counter(text.split(" "))
    return words


def get_ascii(text):
    """
    Generate unicode/ascii values for each character in the text(str)
    and return it as a list.
    """
    return list(map(ord, text))


def to_bytes(as_list):
    """
    Takes a list of ascii values of input text and converts in to 4x4 byte
    of hex values in a format required for AES Rijndael Cipher. Returns the
    parsed text as list of all 4x4 byte blocks of hex values.
    """
    # Apply zero-padding if necessary
    if len(as_list) % 16 != 0:
        x = 16 - len(as_list) % 16
        as_list.extend([0 for i in range(x)])
    byte = [list(as_list[i:i + 4]) for i in range(0, len(as_list), 4)]
    all_blocks = [list(byte[i:i + 4]) for i in range(0, len(byte), 4)]
    return all_blocks


def to_hex_vals(as_list):
    """
    Takes a list of integers and converts them into hex format. Returns the
    output as a list of hex integers.
    """
    hex_strs = [hex(y) for y in as_list]
    hex_ints = [int(hex_strs[i].replace('0x', ''), 16) for i in range(len(hex_strs))]
    return hex_ints


def parse_text(filename):
    """
    This method parses the text from input text file, provided by filename and returns the ascii the value
    of the whole text as an output.
    :param filename: (str) Input text filename
    :return all_blocks: (list) Contains ascii-values of the text.
    :return num_words: (int) Number of words in the text.
    """
    s_text = read_book(filename)
    all_words = count_words_fast(s_text)
    num_words = sum(all_words.values()) - all_words['']
    ascii_vals = get_ascii(s_text)
    all_blocks = to_bytes(ascii_vals)
    return all_blocks, num_words


if __name__ == "__main__":
    filename = "text_samp.txt"
    (all_blocks, numwords) = parse_text(filename)
    for i in range(len(all_blocks)):
        print(len(all_blocks[i]) % 4 == 0)
    print("Number of words in the file = ", numwords)
