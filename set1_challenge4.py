#Set 1: Challenge 4
from set1_challenge3 import byte_cipher_decode

dataset = []
with open("set1_challenge4_input.txt","r") as f:
    dataset = f.readlines()
    
dataset = [bytearray.fromhex(i) for i in dataset]

def character_frequency(b1):
    #return a dictionary of character frequencies, 
    #and the number of times the most used character is used
    chars = {}
    
    for i in range(len(b1)):
        c = b1[i]

        if c not in chars.keys():
            chars[c] = 1
        else:
            chars[c] += 1
            
    m = 0
    for key in chars.keys():
        if chars[key] > m:
            m = chars[key]
    
    return (m, chars)
    
#this prints out the line numbers, sorted by highest frequency. 
#these will be candidates

freq_set = []
for i in range(len(dataset)):
    d = dataset[i]
    f, c = character_frequency(d)
    freq_set.append( (f,i) )

#2 lines have max character frequency of 5
#print(sorted(freq_set, reverse=True))

s = byte_cipher_decode(dataset[170], bytearray(b'\x35')).strip() #clip off \n 
print(f"Set 1, Challenge 4: Pass, '{s}'")
