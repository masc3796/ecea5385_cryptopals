#Set 2, challenge 9

def pkcs7_pad(b1, block_size):
    pad_size = block_size - (len(b1) % block_size)
    assert pad_size < 256
    
    for i in range(pad_size):
        b1 += pad_size.to_bytes(1, "big")
        
    return b1
    
   
b1 = b"YELLOW SUBMARINE"
b2 = pkcs7_pad(b1, 20)
assert b2 == b"YELLOW SUBMARINE\x04\x04\x04\x04"
print(f"Set 2, Challenge 9: Pass, {b2}")

