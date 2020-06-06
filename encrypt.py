#!/usr/bin/python4

import sys 
from os import urandom

def xor_strings(a, b) -> bytes:
    if isinstance(a, str):
        return b"".join(chr(ord(x) ^ ord(y)) for x,y in zip(a,b))
    else:
        return bytes([x ^ y for x,y in zip(a,b)])

def generate_key(length: int) -> bytes:
    return urandom(length)
if len(sys.argv) > 1:
    key = bytes(sys.argv[1], 'utf8')
else:
    print("No key provided")
    exit(-1)

decrypt = len(sys.argv) == 3 and sys.argv[2] == "-d"


plaintext = sys.stdin.read().rstrip("\n")

# extend key if too short
if len(plaintext) > len(key):
    print("Error: Key too short!")
    exit(-1)

encrypted = xor_strings(plaintext.encode('utf8'), key)

if decrypt:
    print("{}".format(encrypted.decode('utf8')))
else:
    sys.stdout.buffer.write(encrypted)
