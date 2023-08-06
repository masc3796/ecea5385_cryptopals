#Set 2, challenge 11

import base64
from Crypto.Cipher import AES
from set2_challenge9 import pkcs7_pad
from set2_challenge10 import ebc_encrypt, ebc_decrypt, cbc_encrypt, cbc_decrypt
from set2_challenge11 import generate_random_key, oracle
import random

global key
key = generate_random_key(16)


def encrypt_ecb_append_string(b1):

    global key
    salt = base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK""")
    b1_padded = pkcs7_pad(b1 + salt, len(key))
    
    return ebc_encrypt(b1_padded, key)
    
def detect_block_size(b1):
    #take advantage of the fixed block size of AES to detect the block size
    #The salting will make some number of blocks output by itself
    #add an increasing length string to it, to see when the block boundary is hit
    #and return the difference as the determined block size

    ciphertext = b""
    len0 = len(encrypt_ecb_append_string(ciphertext))
    
    i = 1
    while True:
        ciphertext += b"\x00"
        this_len = len(encrypt_ecb_append_string(ciphertext))
        if len0 != this_len:
            break
            
        i += 1
    return (this_len-len0)
    
def byte_at_a_time_ecb_decrypt(b1, block_size):
    
    #We know the size of the salt implictly by encrypting empty plaintext
    salt_size = len(encrypt_ecb_append_string(b""))
    
    #decrypt one byte at a time...
    salt = b""

    #Loop re-run the same loop for each character
    for s in range(salt_size):
    
        #this loop derives one byte at a time
        for i in range(256):    
            prefix_size = ((block_size-1) - len(salt)) % block_size
            prefix = b"A"*prefix_size
            
            output_prefix_only = encrypt_ecb_append_string(prefix)                
            output_with_test_byte = encrypt_ecb_append_string(prefix + salt + i.to_bytes(1, "big"))
           
            #Need to compare more bytes as the length of the message grows
            comparison_size = prefix_size + len(salt) 
           
            #only compare one block size worth of data
            if output_prefix_only[:comparison_size] == output_with_test_byte[:comparison_size]:
                salt += i.to_bytes(1, "big")
            else:
                pass
            
    
    return(salt)

    
with open("set2_challenge10_output.txt") as f:
    plaintext = bytes(f.read(), "ascii")

ciphertext = encrypt_ecb_append_string(plaintext)

block_size = detect_block_size(ciphertext)
assert block_size == 16

#Detect ECB mode by ensuring there are repeating strings to detect
mode = oracle(encrypt_ecb_append_string(b"\x00"*(block_size*16)), block_size)
assert mode == 0

plaintext = byte_at_a_time_ecb_decrypt(ciphertext, block_size)
plaintext = plaintext.decode("ascii")

with open("set2_challenge12_output.txt", "w") as f:
    f.write(plaintext)

print(f"Set 2, Challenge 12: Pass")


