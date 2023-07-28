import base64


#Set 1: Challenge 5

s1 = bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ascii")
key = bytes("ICE", "ascii")

def repeating_XOR(s, key):

    i = 0
    ret = [None]*len(s)
    
    for i in range(len(s)):
        ret[i] = s[i] ^ key[i % len(key)]
                
    return bytearray(ret)
        
exp = bytearray.fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
assert exp == repeating_XOR(s1, key)
print("Set 1, Challenge 5: Pass")

