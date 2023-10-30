from functools import reduce
from operator import xor
import os
from PIL import Image

SBOX = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
])

RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def pad(message):
    """
    Pad the given message with bytes to ensure its length is a multiple of 16.

    Parameters:
        message (bytes): The message to be padded.

    Returns:
        bytes: The padded message.
    """
    size = 16 - len(message) % 16
    return message + bytes([size] * size)


def unpad(message):
    """
    Removes padding from a message.

    Parameters:
        message (str): The message to remove padding from.

    Returns:
        str: The message without padding.
    """
    return message[:-message[-1]]


def rotate(list):
    """
    Rotate the given list by doubling it and returning a subset of its elements.

    Parameters:
        list (list): The list to be rotated.

    Returns:
        list: A subset of the rotated list.
    """
    return (list*2)[1:5]


def convert(msg, size):
    """
    Generate a list of blocks from a given message.

    Parameters:
        msg (str): The message to be converted into blocks.
        size (int): The size of each block.

    Returns:
        list: A list of blocks created from the message.
    """
    block_list = []
    
    for letter_index in range(0, len(msg), size):
        block_list.append(msg[letter_index: letter_index + size])

    return block_list

def inc(bytes):
    """
    Increment an integer represented as a byte array by 1 and yield the resulting byte array.

    Parameters:
    - bytes: A byte array representing an integer.

    Returns:
    - A generator that yields byte arrays representing the incremented integer.
    """
    as_int = int.from_bytes(bytes, "big")
    while True:
        as_int += 1
        yield (as_int).to_bytes(16, "big")


def xtime(x):
    """
    Calculate the xtime of a given value.

    Args:
        x (int): The input value.

    Returns:
        int: The xtime of the input value.
    """
    return (((x << 1) ^ 0x1B) & 0xFF) if (x & 0x80) else (x << 1)


def expand_key(key):
    """
    Expand a given key using the AES key expansion algorithm.

    Parameters:
        key (bytes): The original key to be expanded.

    Returns:
        list: A list of expanded keys.

    Algorithm:
        1. Convert the key to words by splitting it into 4-byte chunks.
        2. Iterate from the 4th word to the 44th word.
        3. Set the current word to the previous word.
        4. If the current index is divisible by 4, perform the following operations:
            a. Rotate the current word.
            b. Translate the rotated word using the SBOX lookup table.
            c. XOR each byte of the rotated word with the corresponding byte of the RCON constant and 0s.
        5. Append the result of XORing the current word with the previous 4th word to the words list.
        6. Convert the words list back to bytes by combining each word.
        7. Return the list of expanded keys.
    """
    words = convert(key, 4)
    for i in range(4, 44):
        temp = words[i-1]
        if i % 4 == 0:
            *temp, = map(xor, rotate(temp).translate(SBOX), [RCON[i//4], 0, 0, 0])
        words.append(bytes([*map(xor, words[i-4], temp)]))
    return [b''.join(word) for word in convert(words, 4)]


def add_round_key(state, key):
    """
    Adds the round key to the state.

    Args:
        state (bytes): The current state.
        key (bytes): The round key.

    Returns:
        bytes: The updated state after adding the round key.
    """
    return bytes(map(xor, state, key))


def sub_bytes(state):
    """
    Apply the SubBytes transformation to the state array.

    Args:
        state (bytes): The state array to be transformed.

    Returns:
        bytes: The transformed state array.

    """
    return state.translate(SBOX)


def shift_rows(state, offset=5):
    """
    Shifts the rows of the state matrix by the specified offset.

    Args:
        state (List[int]): The state matrix to shift.
        offset (int, optional): The offset by which to shift the rows. Defaults to 5.

    Returns:
        List[int]: The state matrix with shifted rows.
    """
    return (state * offset)[::offset]

def mix_column(r):
    """
    Mixes the columns of the given list.

    Parameters:
        r (list): A list of integers representing a column.

    Returns:
        list: A list of integers representing the mixed column.
    """
    return [reduce(xor, [a, *r, xtime(a ^ b)]) for a, b in zip(r, rotate(r))]


def mix_columns(state):
    """
    Mixes the columns of the state matrix.

    Args:
        state (list): The state matrix.

    Returns:
        list: The state matrix with columns mixed.
    """
    return [x for r in convert(state, 4) for x in mix_column(r)]


def cipher(block, keys):
    """
    Encrypts a block of data using the AES cipher algorithm.

    Parameters:
    - block (bytes): The block of data to be encrypted.
    - keys (list): A list of round keys used for encryption.

    Returns:
    - bytes: The encrypted block of data.
    """
    state = add_round_key(block, keys[0])
    
    for round in range(1, 11):
        state = sub_bytes(state)
        state = shift_rows(state)
        if round != 10:
            state = mix_columns(state)
        state = add_round_key(state, keys[round])
    return state


def ctr(msg, chave, iv):   
    """
    Encrypts the given message using the AES-CTR encryption algorithm.

    Parameters:
    - msg: The message to be encrypted (bytes).
    - key: The encryption key (bytes).
    - iv: The initialization vector (bytes).

    Returns:
    - The encrypted message (bytes).
    """
    keys =  expand_key(chave)
    blocks = convert(msg, 16)
    ciphers = (cipher(nonce, keys) for nonce in inc(iv))
    ciphered_text = map(add_round_key, blocks, ciphers)
    return b''.join(ciphered_text)




def encrypt_image_with_ctr(image_file, key):
    # Read the image file as binary data
    num_rounds=[1,5,9,13]
    with open(image_file, 'rb') as f:
        image_data = f.read()

    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Encrypt the image data using CTR mode for the specified number of rounds
    encrypted_image_data = image_data
    for _ in num_rounds:
        encrypted_image_data = ctr(encrypted_image_data, key, iv)

        # Save the encrypted image data to a new file for each round
        encrypted_image_file = f"{image_file}.encrypted_round_{_}"
        with open(encrypted_image_file, 'wb') as f:
            f.write(encrypted_image_data)
        
        print(f"Round {_}: Image encrypted and saved as {encrypted_image_file}")

    return encrypted_image_data

def decrypt_image_with_ctr(encrypted_image_file, key):
    # Read the encrypted image file as binary data
    with open(encrypted_image_file, 'rb') as f:
        encrypted_image_data = f.read()

    # Generate the initialization vector (IV) from the encrypted image data
    iv = encrypted_image_data[:16]

    # Decrypt the image data using CTR mode
    decrypted_image_data = ctr(encrypted_image_data[16:], key, iv)

    # Create a new file path for the decrypted image file
    decrypted_image_file = str(encrypted_image_file) + '.decrypted'

    # Save the decrypted image data to a new file
    with open(decrypted_image_file, 'wb') as f:
        f.write(decrypted_image_data)

    return decrypted_image_file

def render_decrypted_image(decrypted_image_file):
    decrypted_image = Image.open(decrypted_image_file)
    decrypted_image.show()
