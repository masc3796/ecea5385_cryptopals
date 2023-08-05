#Set 2, challenge 13
from set2_challenge10 import ebc_encrypt, ebc_decrypt
from set2_challenge11 import generate_random_key
from set2_challenge9 import pkcs7_pad

global block_size 
block_size = 16

global key
key = generate_random_key(block_size)

def parse_cookie(s):
    ret = {}
    
    for ele in s.split("&"):
        sp = ele.split("=")
        key = sp[0]
        val = sp[1]
        
        if not key in ret.keys():
            ret[key] = val
        else:
            raise(ValueError, "Duplicate Key in Cookie")
            
            
    return ret                
            
#Test 1
d1 = {
  'foo': 'bar',
  'baz': 'qux',
  'zap': 'zazzle'
}
d2 = parse_cookie("foo=bar&baz=qux&zap=zazzle")
assert d1 == d2
                
def profile_for(s):
    s = s.replace("&", "")
    s = s.replace("=", "")
    
    return f"email={s}&uid=10&role=user"
    
#Test 2 (example on cryptopals)
d1 = profile_for("foo@bar.com") 
d2 = "email=foo@bar.com&uid=10&role=user"
assert d1 == d2

#Test 3 (injection attack gets rejected)
d1 = profile_for("foo@bar.com&role=admin") 
d2 = "email=foo@bar.comroleadmin&uid=10&role=user"
assert d1 == d2



def ecb_cut_and_paste(block_size):
    
    global key

    #Reference: https://bernardoamc.com/ecb-cut-paste-attack/
    #Note!! Implementation here is still my own, but searched online for inspiration... 
    
    #Exploit the fact that same plaintext always yields same ciphertext
    
    #Get one ciphertext block such that: has the word "admin" + padding
    #   Block 1 contains .... "email= (whatever)"
    #   Block 2 contains .... "admin + (fake pkcs7 padding)" <-- this block will be pasted at the end of the result
    #   Block 3 contains .... "&uid=10&role=user" + (real padding)"
    
    #Create another with carefully chosen values such that:
    #   Block 1 contains .... "email= some_email"
    #   Block 2 contains .... (email) + "&uid=10&role=" (must fill whole block with letters
    #   Block 3 contains .... "user" + padding <-- this block will be ignored
    
    #Then... replace the last block with the one generated previously 
    #Note be careful about STRINGS and BYTES here!!!
    
    #First Block... Block 2 here will be used in the final block
    #"email=" is 6 characters, "admin" is 5, so we still need 5 more
    #use chr here because we're still working with strings!
    dummy_email1 = (block_size-6)*"?" + "admin" + (block_size-5)*chr(block_size-5)
    
    plaintext1 = profile_for(dummy_email1)
    plaintext1 = bytes(plaintext1, "ascii")
    plaintext1 = pkcs7_pad(plaintext1, block_size)
    
    ciphertext1 = ebc_encrypt(plaintext1, key)
    
    #matt@mail.com is carefully chosen so that
    #   Block1 = "email=matt@mail." (16 chars)
    #   Block2 = "com&uid=10&role=" (16 chars)
    #   Block3 = "user" + padding <-- this block will be replaced
    
    dummy_email2 = "matt@mail.com"
    plaintext2 = profile_for(dummy_email2)
    plaintext2 = bytes(plaintext2, "ascii")
    plaintext2 = pkcs7_pad(plaintext2, block_size)
    
    ciphertext2 = ebc_encrypt(plaintext2, key)
    
    admin_ciphertext = ciphertext2[:2*block_size] + ciphertext1[block_size:2*block_size]
  
    return admin_ciphertext
    

admin_ciphertext = ecb_cut_and_paste(block_size)

#Note admin_ciphertextis still pkcs7 padded. Remove it here before returning

admin_plaintext = ebc_decrypt(admin_ciphertext, key)[:-1*(block_size-5)]
admin_plaintext = admin_plaintext.decode("ascii")

cookie = parse_cookie(admin_plaintext)
assert cookie['role'] == 'admin'
print(f"Set 2, Challenge 13: Pass")

