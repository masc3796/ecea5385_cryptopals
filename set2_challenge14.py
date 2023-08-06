#Set 2, challenge 14

import base64
from Crypto.Cipher import AES
from set2_challenge9 import pkcs7_pad
from set2_challenge10 import ecb_encrypt, ecb_decrypt
from set2_challenge11 import generate_random_key, oracle
import random

#This hook is for testing purposes only
global randomize
randomize = True

global key
if randomize:
    key = generate_random_key(16)
else:
    key = b"\x00"*16
    
global random_prefix

if randomize:
    random_prefix = generate_random_key(random.randint(0, 128))
else:
    random_prefix = b"\x00"*22   
    
def encrypt_ecb_append_string(b1):

    global key
    global random_prefix

    salt = base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK""")
    b1_padded = pkcs7_pad(random_prefix + b1 + salt, len(key))
    return ecb_encrypt(b1_padded, key)
    
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
    
def blockify(b1, block_size):
    #utility to break ciphertext into blocks 
    ret = []
    
    for i in range(len(b1)):
        block_num = i // block_size
        idx = i % block_size
        
        try:
            ret[block_num][idx] = b1[i]
        except:
            ret.append([None]*block_size)
            ret[block_num][idx] = b1[i]
            
    return ret
            
    
def detect_prefix_size(b1, block_size):
   
    #first figure out how many whole blocks are used in the prefix
    #this is easy becasue we can encrypt empty and 1-byte messages and simply
    #see where they differ
    message1 = b""
    ciphertext1 = encrypt_ecb_append_string(message1)
    ciphertext1 = blockify(ciphertext1, block_size)
    
    message2 = b"\x00"
    ciphertext2 = encrypt_ecb_append_string(message2)
    ciphertext2 = blockify(ciphertext2, block_size)
    
    whole_blocks = 0
    for i in range(len(ciphertext1)):
        if ciphertext1[i] == ciphertext2[i]:
            whole_blocks += 1
        else:
            break
    
    #now figure out the index in each block by encrypting two 
    #messages side-by-side with +1 length difference. when the 
    #next blocks become equal we know how many extra bytes were
    #needed to reach the bock boundary, and the prefix length is then 
    #whole_blocks + offset
    
    offset = 0
    for i in range(block_size):
        message1 = b"\x00"*i
        message2 = b"\x00"*(i+1)
        
        ciphertext1 = encrypt_ecb_append_string(message1)
        ciphertext1 = blockify(ciphertext1, block_size)
        
        ciphertext2 = encrypt_ecb_append_string(message2)
        ciphertext2 = blockify(ciphertext2, block_size)        
        
        if ciphertext1[whole_blocks] == ciphertext2[whole_blocks]:
            offset = i
            break
            
    prefix_size = whole_blocks*block_size + (block_size - offset)
    return prefix_size
    
    
    
def byte_at_a_time_ecb_decrypt(b1, block_size, random_prefix_size):
    #note this function already has a variable called prefix_size
    #the random one from the encrytption function is called "random_prefix_size"
    
    #We know the size of the salt implictly by encrypting empty plaintext
    #Change for Challeneg 14: subtracted off random_prefix_size here
    salt_size = len(encrypt_ecb_append_string(b"")) - random_prefix_size
    
    #decrypt one byte at a time...
    salt = b""

    #Loop re-run the same loop for each character
    for s in range(salt_size):
    
        #this loop derives one byte at a time
        for i in range(256):
            #Change for Challenge 14: subtract off random_prefix_size
            prefix_size = ((block_size-1) - random_prefix_size - len(salt)) % block_size
            prefix = b"A"*prefix_size
            
            output_prefix_only = encrypt_ecb_append_string(prefix)
            output_with_test_byte = encrypt_ecb_append_string(prefix + salt + i.to_bytes(1, "big"))
           
            #Need to compare more bytes as the length of the message grows
            #Change for Challenge 14: ADD random_prefix_size
            comparison_size = prefix_size + len(salt) + random_prefix_size 
           
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

prefix_size = detect_prefix_size(ciphertext, block_size)
assert prefix_size == len(random_prefix)

#Detect ECB mode by ensuring there are repeating strings to detect
mode = oracle(encrypt_ecb_append_string(b"\x00"*(block_size*16)), block_size)
assert mode == 0

plaintext = byte_at_a_time_ecb_decrypt(ciphertext, block_size, prefix_size)
plaintext = plaintext.decode("ascii")

with open("set2_challenge14_output.txt", "w") as f:
    f.write(plaintext)

print(f"Set 2, Challenge 14: Pass")


