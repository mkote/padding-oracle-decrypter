# pypoa - python padding oracle attack
Tool for decrypting CBC encrypted ciphertexts using the padding oracle attack

## Usage
1. Implement a function that queries the oracle.
2. Import pypoa's OracleAttack class.
3. Instantiate OracleAttack class with the oracle function
4. Call `attack.execute(ciphertext)` on the ciphertext to leak it.

```python
import decrypt
from decrypt import OracleAttack

# Define an oracle function
def localOracle(cipherText: bytearray):
    key = b"Sixteen byte key" # Secret
    iv = cipherText[:AES.block_size]
    ct = cipherText[AES.block_size:]
    try:
        decrypt(ct, iv, key)
        return True
    except:
        return False
        
       
data = b"secret" # Secret
key = b"Sixteen byte key" #Secret 
iv = b"/kQ\x0bDZ\xc6F\xb2\xc4\x9c\xca\x8c\'!]"
cipherText = b'VS&\xcb\xa7\xa5<\x14d\x00j\xe6\xb5\xba\xad\x08'
ct = iv+cipherText
attack = OracleAttack(localOracle)
decrypted = attack.execute(iv+cipherText)
 ```


