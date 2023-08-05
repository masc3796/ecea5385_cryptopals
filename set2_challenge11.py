#Set 2, challenge 11

from Crypto.Cipher import AES
from set2_challenge10 import ebc_encrypt, ebc_decrypt, cbc_encrypt, cbc_decrypt
from set2_challenge9 import pkcs7_pad
import random

def generate_random_key(key_size):
    ret = b""
    for i in range(key_size):
        r = random.randint(0, 255)
        ret += r.to_bytes(1, 'big')
    return ret
        
def encrypt_ebc_cbc_random(b1, key_size):

    key = generate_random_key(key_size)    
    pad_size = random.randint(5, 10)
    b1_padded = random.randbytes(pad_size) + b1 + random.randbytes(pad_size)
    b1_padded = pkcs7_pad(b1_padded, key_size)
        
    mode = random.choice([0, 1])

    if mode == 0: #ECB mode
        return (ebc_encrypt(b1_padded, key), mode)
    
    else: #CBC mode
        iv = generate_random_key(key_size)
        return (cbc_encrypt(b1, key, key_size, iv), mode)
        
def oracle(b1, block_size):

    #this block from challenge #8 detects ECB Mode

    #break each line up into blocks of block_size in length
    blocks = []
    for i in range(0, len(b1), block_size):
        blocks.append(b1[i:i+block_size-1])
        
    #converting to a set will REMOVE duplicates
    if len(blocks) != len(set(blocks)):
        return 0 #E.g. ECB mode
        
    else:
        return 1 #E.g CBC mode


    
with open("set2_challenge10_output.txt") as f:
    plaintext = bytes(f.read(), "ascii")
        
for i in range(100):
    ciphertext, mode_used = encrypt_ebc_cbc_random(plaintext, 16)
    mode_detected = oracle(ciphertext, 16)
    #print(i, mode_used, mode_detected)
    
    assert mode_used == mode_detected

print(f"Set 2, Challenge 11: Pass")
    
