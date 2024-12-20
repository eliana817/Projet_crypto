'''code repris d'un write up je suis incapable de coder ça, mais c'est le résultat de ce que l'on doit faire'''


import binascii
import base64
import string

keyMaxSize=40 

def validChars():
    chars = string.ascii_letters + " "
    return chars

def hex2bytes(input):
    return bytes(int(''.join(c), 16) for c in zip(input[0::2],input[1::2])) 

def hex2bin(s):
    return bin(int(binascii.hexlify(s),16))

#----------------------------------------------------------------------------------------------------------------------------------------

def charFrequency(letter):
    frequencyTable ={
        'A': 0.0651738, 'B': 0.0124248, 'C': 0.0217339, 'D': 0.0349835, 'E': 0.1041442,
        'F': 0.0197881, 'G': 0.0158610, 'H': 0.0492888, 'I': 0.0558094, 'J': 0.0009033,
        'K': 0.0050529, 'L': 0.0331490, 'M': 0.0202124, 'N': 0.0564513, 'O': 0.0596302,
        'P': 0.0137645, 'Q': 0.0008606, 'R': 0.0497563, 'S': 0.0515760, 'T': 0.0729357,
        'U': 0.0225134, 'V': 0.0082903, 'W': 0.0171272, 'X': 0.0013692, 'Y': 0.0145984,
        'Z': 0.0007836, ' ': 0.1918182
    }
    letterFrequency = frequencyTable.get(letter, 0)
    return letterFrequency

def singleXOR(bytes1):
    xorKey = ''
    maxScore = 0
    for key in range(256): 
        xor = ''.join(chr(byte ^ key) for byte in bytes1)
        xorScore = stringScore(xor) 
        if xorScore > maxScore:
            maxScore = xorScore
            xorKey = chr(key)
            xorString = xor
    return xorString, xorKey

def stringScore(string):
    totalScore = 0
    for letter in string:                         
        if letter in str(validChars()): 
            charScore = charFrequency(letter.upper())        
            totalScore += charScore
    return totalScore

#----------------------------------------------------------------------------------------------------------------------------------------

def repeated_KeyXOR(s,key):
    return bytes(s[i] ^ key[i % len(key)] for i in range(max(len(s),len(key)))) 

def break_repeating_keyXor(ciphertext,possible_keys):
    score =0
    maxScore=0
    plaintext = ""
    cipher_key = ""
    for key in possible_keys:
        possible_plaintext = repeated_KeyXOR(ciphertext,key.encode()) 
        score = stringScore(possible_plaintext.decode()) 
        if score > maxScore:
            maxScore = score
            plaintext = possible_plaintext.decode()
            cipher_key = key
    
    return cipher_key,plaintext

#----------------------------------------------------------------------------------------------------------------------------------------

def hammingDistance(s1, s2):
    if len(s1) != len(s2):
        ValueError('Values must be equal length')
    distance = bin(int(binascii.hexlify(s1),16) ^ int(binascii.hexlify(s2),16)).count("1")
    return distance


def get_probable_key_size(cipher):    
    if keyMaxSize >= len(cipher)//4: 
        raise ValueError('Key Max Size length can\'t be higher of a quarter half the ciphertext size')
    fcb = "" # first cipher bytes
    scb = "" # second cipher bytes
    tcb = "" # third cipher bytes
    qcb = "" # quarter cipher bytes

    normalizedHammingDistance = {}

    for keySize in range(2,keyMaxSize):       
        fcb = cipher[:keySize]
        scb = cipher[keySize:len(cipher)-(len(cipher)-(2*keySize))] 
        tcb = cipher[2*keySize:len(cipher)-(len(cipher)-(3*keySize))]
        qcb = cipher[3*keySize:len(cipher)-(len(cipher)-(4*keySize))]
        normalizedHammingDistance[keySize] = (hammingDistance(fcb,scb)+ hammingDistance(scb,tcb) + \
            hammingDistance(tcb,qcb)) / (keySize * 3) 
    problable_keysizes = {values: keys for values, keys in sorted(normalizedHammingDistance.items(), key=lambda value: value[1])[:4]}   
    return list(problable_keysizes.keys()) 

#----------------------------------------------------------------------------------------------------------------------------------------

def cipherBlocks(guess_keys,cipher):
    cipherText_blocks ={}
    transpose_blocks = {}
    transpose_cipher ={}
    block =""    
    
    for keySize in guess_keys:                    
        cipherText_blocks[keySize] = []
        transpose_cipher[keySize] = []
        transpose_blocks[keySize]= []
        lastIndex=0
        block=b''
        
        temp_blocks = [] 
        for k in range(0,len(cipher)+1,keySize): 
           
            block = bytes(cipher[lastIndex:k]) 
            transpose_block =b''
            
            for j in range(0,len(block)):

                if len(temp_blocks)-1 < j: 
                    temp_blocks.append(bytes([block[j]])) 
                else:
                    temp_blocks[j] +=  bytes([block[j]])   

            lastIndex = k 

        transpose_blocks[keySize] = temp_blocks 
            
    return transpose_blocks

#----------------------------------------------------------------------------------------------------------------------------------------

def find_keys(blocks):
    possible_keys=[]
    best_score =0
    key_xor = ""
    for key in blocks:
        xor_key = ""
        plaintext = ""
        for block in blocks[key]:
            msg, key = singleXOR(block)
            xor_key += key
            plaintext += msg
        possible_keys.append(xor_key)
    return possible_keys

#----------------------------------------------------------------------------------------------------------------------------------------

def main():
    s1 = "this is a test".encode()
    s2 = "wokka wokka!!!".encode()
    
    with open("6.txt") as file:

        cipher = ""
        for input in file:
            cipher += input.strip('\n')
        cipher = base64.b64decode(cipher)        

        guess_keys = get_probable_key_size(cipher)
        blocks = cipherBlocks(guess_keys,cipher)
        possibleKeys = find_keys(blocks)
        key,plaintext = break_repeating_keyXor(cipher,possibleKeys)

        print("Key: "+key+"\n\nOriginal Message:\n\n"+plaintext)

if __name__ == "__main__":
    main()