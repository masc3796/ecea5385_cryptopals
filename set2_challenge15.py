#Set 2, challenge 15

def validate_pkcs7(b1):

    #last character should be the pad size
    last_char = b1[-1:]
    pad_size = int.from_bytes(last_char, "big")
    last_n_bytes = b1[-1*pad_size:]
    
    #check all last n bytes are equal to pad size
    test = True
    
    for i in range(len(last_n_bytes)):
        if last_char != last_n_bytes[i].to_bytes(1, "big"):
            test = False
           
    #check the value is equal to the pad size
    test = test & (len(last_n_bytes) == pad_size)
    
    if not test:
        raise ValueError("Invalid pkcs7 padding")
    
    return b1[:-1*pad_size]
    
#Test 1
b1 = b"ICE ICE BABY\x04\x04\x04\x04"
b2 = validate_pkcs7(b1)
assert b2 == b"ICE ICE BABY"

#Test 2 - throws a ValueError due to incorrect pad size
b1 = b"ICE ICE BABY\x05\x05\x05\x05"

try:
    validate_pkcs7(b1)
    test = False
except ValueError:
    test = True

assert test == True

#Test 3 - throws a ValueError due to non-equal padding bytes
b1 = b"ICE ICE BABY\x01\x02\x03\x04"

try:
    validate_pkcs7(b1)
    test = False
except ValueError:
    test = True

assert test == True

print(f"Set 2, Challenge 15: Pass")
