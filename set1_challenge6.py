import base64
from set1_challenge3 import byte_cipher_decode
from set1_challenge5 import repeating_XOR

#Set 1, challenge #6

def hamming_distance(b1, b2):
    assert len(b1) == len(b2)
    
    dist = 0
    for i in range(len(b1)):
        ele1 = b1[i]
        ele2 = b2[i]
        
        for j in range(0, 8):
            mask = 1 << j
            if (ele1 & mask) != (ele2 & mask):
                dist += 1
    return dist
    
def character_histogram_score(b1):
    #https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
    english = {
        'E' : 0.111607, 
        'A' : 0.084966, 
        'R' : 0.075809, 
        'I' : 0.075448, 
        'O' : 0.071635, 
        'T' : 0.069509, 
        'N' : 0.066544, 
        'S' : 0.057351, 
        'L' : 0.054893, 
        'C' : 0.045388, 
        'U' : 0.036308, 
        'D' : 0.033844, 
        'P' : 0.031671, 
        'M' : 0.030129, 
        'H' : 0.030034, 
        'G' : 0.024705, 
        'B' : 0.020720, 
        'F' : 0.018121, 
        'Y' : 0.017779, 
        'W' : 0.012899, 
        'K' : 0.011016, 
        'V' : 0.010074, 
        'X' : 0.002902, 
        'Z' : 0.002722, 
        'J' : 0.001965, 
        'Q' : 0.001962, 
        ' ' : 0.2,  #added from google
        'other' : 0.01,  #this is arbitrary
    }
    
    #compute character frequency
    chars = {}
    for i in range(len(b1)):
        c = b1[i]
        
        if chr(c).upper() in english.keys():
            c = chr(c).upper()
        else:
            c = "other"
            
        if c not in chars.keys():
            chars[c] = 1
            
        else:
            chars[c] += 1
            
    #normalize to string length
    for key in chars.keys():
        chars[key] /= len(b1)
                
    #now score by comparing the computed histogram to english.
    #non-letter characters are arbitrarily assigned a 1%
    #lower score (lower abs. error) will be better
    score = 0
    for key in chars.keys():
        score += abs(chars[key] - english[key])
        
    return score

def break_single_XOR(b1):

    scores = []
    #loop through all 256 possible keys
    for key in range(0, 256):
        
        b1_xor = [None]*len(b1)
        for i in range(len(b1)):
            b1_xor[i] = b1[i] ^ key
            
        b1_xor = bytearray(b1_xor)
        score = character_histogram_score(b1_xor)
        scores.append((score, key.to_bytes(1, "big")))
        
    return sorted(scores)
        

#These functions were added new in challenge 6 so re-checking them against the challenge 3
b1 = bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
key_candidates = break_single_XOR(b1)
b1_decode = byte_cipher_decode(b1, key_candidates[0][1]) #This tries only the most likely candidate     
assert b1_decode == "Cooking MC's like a pound of bacon"


#check the hamming distance against the example    
b1 = bytes("this is a test", "ascii")
b2 = bytes("wokka wokka!!!", "ascii")

assert hamming_distance(b1, b2) == 37

dataset = []
with open("set1_challenge6_input.txt","r") as f:
#    dataset = f.readlines()
#dataset = base64.b64decode("".join([i.strip() for i in dataset]))
    dataset = f.read()
dataset = base64.b64decode(dataset)

#For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
edit_distances = []
for keysize in range(2, 41):

    blocks = [[]]*4    
    for i in range(0, 4):
        blocks[i] = dataset[i*keysize:(i*keysize+keysize)]

    avg_hamming_distance = 0    
    for i in range(0, 4):
        first = blocks[i]
        second = blocks[(i+1)%4]
        avg_hamming_distance += hamming_distance(first, second)
           
    avg_hamming_distance /= 4.0 
    avg_hamming_distance /= keysize #normalize to keysize
    
    edit_distances.append((avg_hamming_distance, keysize))
#print(sorted(edit_distances))

#Take the 4 most likely keysizes and proceed
likely_keysizes = [i[1] for i in sorted(edit_distances)[:4]]
#print(likely_keysizes)

possible_keys = []
for keysize in likely_keysizes:
    key = []
    for i in range(keysize):
        transpose = []
        for j in range(i, len(dataset), keysize):
            transpose.append(dataset[j])
            
        key.append(sorted(break_single_XOR(bytes(transpose)))[0][1])
    
    key = b''.join(key)
    possible_keys.append((keysize, key))
    
#print(possible_keys)
#[(3, b'\x80\x80R'), (5, b'O\x80\x80\x80O'), (29, b'Terminator X: Bring the noise'), (2, b'\x80\x80')]
#Keysize 29, and Key="Terminator X: Bring the noise"
#Proceed with that key and decode

key = possible_keys[2][1]
with open("set1_challenge6_output.txt", "w") as f:
    f.write("Key: \n")
    f.write(key.decode("ascii"))
    f.write("\n\nPlaintext: \n\n")
    f.write(repeating_XOR(dataset, key).decode("ascii"))

#key_candidates = [None]*keysize
#for i in range(keysize):
#    key_candidates[i] = break_single_XOR(transpose[i]) 
#print(key_candidates)

print(f"Set 1, Challenge 6: Pass, '{key}'")

