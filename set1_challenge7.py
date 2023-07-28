import base64
from Crypto.Cipher import AES

with open("set1_challenge7_input.txt") as f:
    ciphertext = base64.b64decode(f.read())

cipher = AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)

with open("set1_challenge7_output.txt","w") as f:
    f.write(plaintext.decode("ascii"))
    
print(f"Set 1, Challenge 7: Pass")

