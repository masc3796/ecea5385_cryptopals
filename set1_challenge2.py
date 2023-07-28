def fixed_XOR(b1, b2): 
    assert len(b1) == len(b2), "fixed XOR on different length numbers. Zero-pad first"
    
    ret = [None]*len(b1)
    for i in range(len(b1)):
        ret[i] = b1[i] ^ b2[i]
        
    return bytearray(ret)
    
b1 = bytearray.fromhex("1c0111001f010100061a024b53535009181c")
b2 = bytearray.fromhex("686974207468652062756c6c277320657965")

s1p2 = fixed_XOR(b1, b2)
assert s1p2 == bytearray.fromhex("746865206b696420646f6e277420706c6179")
print("Set 1, Challenge 2: Pass")

