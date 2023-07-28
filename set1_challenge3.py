#Set 1: Challenge 3

def byte_cipher_decode(s, key):
    assert len(key) == 1
    key = key[0]
    
    ret = [None]*len(s)
    for i in range(len(s)):
        try:
            ret[i] = s[i] ^ key
        except:
            ret[i] = 0x00                        
    
    try: 
        ret = bytearray(ret).decode("ascii")
        return ret
    except:
        return ""

b1 = bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

#this block helped figure out the key by brute force
#for i in range(0, 255):
#    key = i.to_bytes(1, "big")
#    print(i, byte_cipher_decode(b1, key))

s = byte_cipher_decode(b1, bytearray(b'\x58'))
print(f"Set 1, Challenge 3: Pass. '{s}'")
