from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64encode
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import traceback
import logging
import binascii

# We assume that the key was securely shared beforehand

debugDecrypt = True

def toHex(byteArray: bytearray):
    return ''.join('0x{:02x} '.format(x) for x in byteArray)


def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv, ct_bytes


def decrypt(ct, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        padded = cipher.decrypt(ct)
    except:
        raise

    if debugDecrypt:
        print("Padded : {}".format(padded))
    try:
        pt = unpad(padded, AES.block_size)
    except:
        raise

    if debugDecrypt:
        print("Unpadded: {}".format(pt))

    return pt, padded

# Leaks the pos'th byte of the ciphertext
def leakByte(pos: int, targetCiphertextBlock: bytearray, precendingBlock: bytearray, fakePadding: int, key : bytes, firstTime : bool):

    # try modifying the last byte of the block until we no longer get a padding error.
    modified = precendingBlock[:]
    oldByte = modified[pos]
    for i in range(0, 256):
        #print("Trying to inject 0x{:02X} as the {}th byte".format(i,pos+1))
        #print("Unmodified ciphertext byte: 0x{:02X}".format(oldByte))

        payload = precendingBlock[pos] ^ i

        # First time we want to ensure that the byte is modified
        #
        #if payload == oldByte and firstTime:
        #    if debugDecrypt:
        #        print("Skipping byte: 0x{:02X}".format(i))
        #    continue

        #print("before", modified)
        #print("Replacing 0x{:02X} with 0x{:02X}".format(oldByte, i))
        modified[pos] = payload
        #print("after", modified)

        # Check for padding error
        try:
            modifiedBytes = bytes(modified)
            ctBytes = bytes(targetCiphertextBlock)
            decrypted, padded = decrypt(ctBytes, modifiedBytes, key)

            if debugDecrypt:
                print("Found a modified byte that did not cause padding error: 0x{:02X}".format(payload))
                print("Padded {}".format(padded))
                print("Unpadded {}".format(decrypted))

            # Obtain plaintext byte
            plaintextByte = payload ^ oldByte ^ fakePadding

            if debugDecrypt:
                print("Decrypted byte 0x{:02X}".format(plaintextByte))

            return plaintextByte, oldByte
            #print("Plaintext (padding) byte is 0x{:02X} ^ 0x{:02X} ^ 0x01 = 0x{:02X}".format(i, oldByte, 1))

        except Exception as err:
            if str(err.args[0]) == 'PKCS#7 padding is incorrect.' or str(err.args[0]) == 'Padding is incorrect.':
                continue
            else:
                raise err

# Modifies the nth byte in block such that when the block is used in CBC decryption it will yield the wanted byte in the next block
def modifyByte(n, block, originalCipherTextByte, plainTextByte, wantedByte):
    #print("Block is {}".format(block))
    # Save old byte
    oldByte = originalCipherTextByte
    nextModifiedByte = plainTextByte ^ oldByte ^ wantedByte

    if debugDecrypt:
        print("Calculated that byte 0x{:02X} should be injected to obtain 0x{:02X} in as the {}th byte".format(nextModifiedByte, wantedByte, n+1))

    modified = block[:]
    modified[n] = nextModifiedByte

    if debugDecrypt:
        print("Modified block is [{}]".format(toHex(modified)))

    return modified

def splitCipherTextIntoBlockPairs(cipherTextBytes: bytearray):
    blocks = [(cipherTextBytes[i:i+AES.block_size]) for i in range(0,len(cipherTextBytes), AES.block_size)]

    pairs = [(blocks[i-1],blocks[i]) for i in range(1, len(blocks), 1)]

    return pairs

def decryptPair(block1 : bytearray, block2 : bytearray, key : bytes):

    # Goal is to decryt block2 using block1
    targetCiphertextBlock = block2[:]
    decryptedBlock = bytearray(len(targetCiphertextBlock))
    precendingBlockCipherText = block1[:]
    firstTime = True

    fakePadding = 0x01
    for pos in range(len(block2)-1, -1, -1):
        if debugDecrypt:
            print("--------------------------")
        if debugDecrypt:
            print("Trying to decipher {}th byte".format(pos+1))

        try:
            # 1. Leak the plaintext byte pos at pos - key is just used to emulate padding oracle
            plaintextByte, _ = leakByte(pos, targetCiphertextBlock, precendingBlockCipherText, fakePadding, key, firstTime)
            firstTime = False
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
            precendingBlockCipherText = modifyByte(j, precendingBlockCipherText, block1[j], ptbyte, fakePadding)

    return bytes(decryptedBlock)

def paddingOracleAttackDecrypt(
    data : bytes, 
    key : bytes, 
    iv_bytes : bytes, 
    ct_bytes : bytes):
    #iv_bytes, ct_bytes = encrypt(data, key)

    cipherText = bytearray(ct_bytes)
    iv = bytearray(iv_bytes)

    if debugDecrypt:
        print("CipherText is [{}]".format(cipherText))
        print("Plaintext is [{}]".format(data))
        print("IV is {}".format(iv))

    # Split ciphertext into block pairs
    pairs = splitCipherTextIntoBlockPairs(iv+cipherText)

    decrypted = bytearray(0)

    for pair in pairs:
        # Key is only used for padding oracle. 
        decryptedBlock = decryptPair(pair[0], pair[1], key)
        decrypted.extend(decryptedBlock)

    return bytes(decrypted)
