#Set 2, challenge 16

import base64
from Crypto.Cipher import AES
from set2_challenge9 import pkcs7_pad
from set2_challenge10 import cbc_encrypt, cbc_decrypt
from set2_challenge11 import generate_random_key
from set2_challenge14 import blockify
import random

global key
global block_size
global iv

block_size = 16
key = generate_random_key(block_size)
iv = generate_random_key(block_size)

block_size = 16
#key = b"\x02"*block_size
#iv = b"\x00"*block_size

def cbc_encrypt_user_input(s, key, block_size, iv):
    s = s.replace(';', '')
    s = s.replace('=', '')
    plaintext = "comment1=cooking%20MCs;userdata=" + s + ";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = bytes(plaintext, "ascii")
    plaintext = pkcs7_pad(plaintext, len(key))
    
    return cbc_encrypt(plaintext, key, block_size, iv)
    
def cbc_decrypt_check_for_substring(ciphertext, sub, key, block_size, iv):
    plaintext = cbc_decrypt(ciphertext, key, block_size, iv)
    return (sub in plaintext)
    


#These characters are carefully chosen such that they are valid ascii characters
#and have known single-bit errors to the characters we want to insert

# Semicolon ==> 1 bit error ==> Colon
semicolon_1bit_error = chr(0x3B ^ 0x01) 

# Equal ==> 1 bit error ==? Less Than 
equal_1bit_error = chr(0x3D ^ 0x01)

#The input String is carefully chosen so that only 1 block will be modified
#"lorem" is just filler text 
plaintext = f"lorem{semicolon_1bit_error}admin{equal_1bit_error}true"
ciphertext_unmod = cbc_encrypt_user_input(plaintext, key, block_size, iv)

#Modify the ciphertext directly... 
ciphertext_mod = list(ciphertext_unmod)

#create the bit error 1 block backward
ciphertext_mod[32+5-16] ^= 0x01
ciphertext_mod[32+11-16] ^= 0x01
ciphertext_mod = bytes(ciphertext_mod)

assert cbc_decrypt_check_for_substring(ciphertext_mod, b";admin=true;", key, block_size, iv)
print(f"Set 2, Challenge 16: Pass")

