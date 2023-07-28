import base64

def hex_to_base64(num):
    b = bytearray.fromhex(num)
    return base64.standard_b64encode(b)
    
s1p1 = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
assert s1p1 == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
print("Set 1, Challenge 1: Pass")
