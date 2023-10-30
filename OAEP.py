from hashlib import sha1
from os import urandom
import hashlib

def mask(data, seed, mlen):
    txt = b''
    for i in range(0, mlen, 20):
        c = i.to_bytes(4, "big")
        txt += hashlib.sha1(seed + c).digest()

    return bytes(a ^ b for a, b in zip(data, bytes(len(data)) + txt[:mlen]))


def cypher_oaep(n, session_key):
    k = (n.bit_length() + 7) // 8
    key_len = len(session_key)
    hash_len = 20

    lable_hash = b"\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t"

    padding_string = b"\x00" * (k - key_len - 2 * hash_len - 2)

    data_block = lable_hash + padding_string + b'\x01' + session_key

    seed = urandom(hash_len)

    masked_data_block = mask(data_block, seed, k - hash_len - 1)
    masked_seed = mask(seed, masked_data_block, hash_len)

    return b'\x00' + masked_seed + masked_data_block


def decypher_oaep(n, msg_cifrada):
    k = (n.bit_length() + 7) // 8
    tam_hash = 20

    _, masked_seed, masked_data_block = msg_cifrada[:1], msg_cifrada[1:1 + tam_hash], msg_cifrada[1 + tam_hash:]

    seed = mask(masked_seed, masked_data_block, tam_hash)

    data_block = mask(masked_data_block, seed, k - tam_hash - 1)

    msg = data_block.split(b'\x01', 1)[1]

    return msg
