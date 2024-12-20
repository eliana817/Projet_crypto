import binascii
from chall1 import hex2binary

cypher = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
hex1 = binascii.unhexlify(cypher)

def scoring(cypher):
    """
    Gives a score to the inputed string based on how english it is.
    This function bases itself on character frequency.

    - cypher: the string to which we wish to provide a score

    Returns: score
    """
    score = 0
    letter_freq = "ETAOIN SHRDLU"
    freq = {}
    cypher = cypher.upper()

    for char in cypher:
        if char not in freq:
            freq[char] = 1
        else:
            freq[char] += 1
    
    sorted_freq = dict(sorted(freq.items(), key=lambda item: item[1], reverse=True))

    for key, _ in sorted_freq.items():
        if key in letter_freq:
            score += 1

    return score


for k in range(256):
    result = ''.join(chr(k ^ part) for part in hex1)
    score = scoring(result)
    if 6 < score <= 13: #based on the 13 most used characters including the space (13 highest score, 7 is the lowest score, meaning least english like)
        print(result, chr(k)) #We could also decide to print only the results with the highest scores to be even more precise (see chall 4)

#Keys are:
# X --> Cooking MC's like a pound of bacon (score 10)
# x --> cOOKINGmcSLIKEAPOUNDOFBACON (score 9)
    