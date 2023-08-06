#Set 2, challenge 10

#from set2_challenge9 import pkcs7_pad
import base64
from Crypto.Cipher import AES
from set1_challenge2 import fixed_XOR as byte_xor


def ebc_encrypt(b1, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(b1)
    
#This is a hack due to discovering a typo in the name of the function waay to late
def ecb_encrypt(b1, key):
    return ebc_encrypt(b1, key)

def ebc_decrypt(b1, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(b1)
    
def ecb_decrypt(b1, key):
    return ebc_decrypt(b1, key)
        
def cbc_encrypt(b1, key, block_size, iv):

    ret = b''
    last_output = iv
    
    for i in range(0, len(b1), block_size):
        this_block = b1[i:i+block_size]
        ebc_in = byte_xor(this_block, last_output)
        
        ebc_out = ebc_encrypt(ebc_in, key)
        ret += ebc_out
        last_output = ebc_out
        
    return ret
    
    
def cbc_decrypt(b1, key, block_size, iv):

    ret = b''
    last_output = iv
    
    for i in range(0, len(b1), block_size):
        this_encr = b1[i:i+block_size]
        this_decr = ebc_decrypt(this_encr, key)
        
        ret += byte_xor(this_decr, last_output)
        last_output = this_encr

    return ret
    
with open("set2_challenge10_input.txt") as f:
    ciphertext = base64.b64decode(f.read())
    
block_size = 16
key = b"YELLOW SUBMARINE"
iv = b"\x00"*block_size    
plaintext = cbc_decrypt(ciphertext, key, block_size, iv)
plaintext = plaintext.decode("ascii")

with open("set2_challenge10_output.txt", "w") as f:
    f.write(plaintext)
    
print(f"Set 2, Challenge 10: Pass")
