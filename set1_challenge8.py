import base64

with open("set1_challenge8_input.txt") as f:
    ciphertext = f.readlines()

#since we are only looking for duplicates, we will treat lines as STRINGS
ciphertext = [i.strip() for i in ciphertext]

#This is a semi-guess based on the problem statement in cryptopals
block_size = 16

#to detect AES-ECB...
#check how many times a duplicate set of blocks is found in a line in the file
line_num = 0

for line in ciphertext:

    #break each line up into blocks of block_size in length
    blocks = []
    for i in range(0, len(line), block_size):
        blocks.append(line[i:i+block_size-1])
        
    #converting to a set will REMOVE duplicates
    if len(blocks) != len(set(blocks)):
        print(f"AES-ECB detected on line {line_num}")        
    
    line_num += 1
    
