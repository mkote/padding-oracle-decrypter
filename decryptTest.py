import decrypt

def testPaddingOracleAttack01():
    data = b"secret"
    key = b"Sixteen byte key" 
    iv = b"/kQ\x0bDZ\xc6F\xb2\xc4\x9c\xca\x8c\'!]"
    cipherText = b'VS&\xcb\xa7\xa5<\x14d\x00j\xe6\xb5\xba\xad\x08'
    decrypted = decrypt.paddingOracleAttackDecrypt(data, key, iv, cipherText)

    assert(data == decrypted[:len(data)])

def testPaddingOracleAttack02():
    data = b"secret"
    key = b"Sixteen byte key" 
    iv = b'\x1b\xce\xe6vW\xbc\xc5\x97\x13ilc\x08,\xcf\x11' 
    cipherText = b'\x0b6\xa2\xc9\xb5\xc4\xc0\x05\x00t\xf5v\xb5\x18[-' 
    decrypted = decrypt.paddingOracleAttackDecrypt(data, key, iv, cipherText)

    assert(data == decrypted[:len(data)])

def testPaddingOracleAttack03():
    data = b"secret"
    key = b"Sixteen byte key" 
    iv, cipherText = decrypt.encrypt(data, key)
    iv = b'D\t\xefi\xcf\xf5\xbd3\xb0\xf2x\x80e\xe3\xe7\xd2'
    cipherText = b'\xaa\xb0T\xe4\xeb\xe2\xf7\x91)Xf\xdeH\xb1\x1a\x89'

    decrypted = decrypt.paddingOracleAttackDecrypt(data, key, iv, cipherText)

    assert(data == decrypted[:len(data)])

def testFourBlocks():
    data = b"A"*((16*2)+15)
    key = b"Sixteen byte key" 
    iv, cipherText = decrypt.encrypt(data, key)
    #iv = b'\x1b\xce\xe6vW\xbc\xc5\x97\x13ilc\x08,\xcf\x11' 
    #cipherText = b'\x0b6\xa2\xc9\xb5\xc4\xc0\x05\x00t\xf5v\xb5\x18[-' 
    try:
        decrypted = decrypt.paddingOracleAttackDecrypt(data, key, iv, cipherText)
    except Exception as err:
        pass

    assert(data == decrypted[:len(data)])

def runAllTests():
    print(".", end='')
    testPaddingOracleAttack01()
    print(".", end='')
    testPaddingOracleAttack02()
    print(".", end='')
    testPaddingOracleAttack03()
    print(".", end='')
    testFourBlocks()
    #
    #while True:
    #    testPaddingOracleAttackFuzz()
    print(" All tests passed!")

runAllTests()
