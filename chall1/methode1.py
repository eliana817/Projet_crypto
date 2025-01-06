from base64 import b64encode

cypher = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

#Methode 1
print("Methode 2")
b64 = b64encode(bytes.fromhex(cypher)).decode()
print(b64)


#Methode 2
def hex2binary(cypher):
    """
    Converts hexadecimal to binary

    - cypher: the hex to convert

    Returns: the binary value
    """
    dec = int(cypher, 16)
    bin = ''
    while dec !=0:
        result = dec % 2
        bin = f"{result}" + bin
        dec = dec // 2
    return bin

def hex2b64(cypher):
    """
    Converts hexadecimal to base 64.

    - cypher: the hexadecimal to convert to base 64

    Return: the base64 value
    """
    encode = ""
    index = {0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E', 5: 'F',
             6: 'G', 7: 'H', 8: 'I', 9: 'J', 10: 'K', 11: 'L',
             12: 'M', 13: 'N', 14: 'O', 15: 'P', 16: 'Q', 17: 'R',
             18: 'S', 19: 'T', 20: 'U', 21: 'V', 22: 'W', 23: 'X',
             24: 'Y', 25: 'Z', 26: 'a', 27: 'b', 28: 'c', 29: 'd',
             30: 'e', 31: 'f', 32: 'g', 33: 'h', 34: 'i', 35: 'j',
             36: 'k', 37: 'l', 38: 'm', 39: 'n', 40: 'o', 41: 'p',
             42: 'q', 43: 'r', 44: 's', 45: 't', 46: 'u', 47: 'v',
             48: 'w', 49: 'x', 50: 'y', 51: 'z', 52: '0', 53: '1', 54: '2',
             55: '3', 56: '4', 57: '5', 58: '6', 59: '7', 60: '8', 61: '9',
             62: "+", 63: "/"}
   
    bin = hex2binary(cypher)

    pad = 6 - len(bin) % 6
    bin = "0"*pad + bin

    for i in range(0, len(bin), 6):
        part = bin[slice(i,i+6)]
        encode += index[int(part, 2)]

    return encode

print("Methode 3")
print(f"\nHexadecimal: {cypher} \nBase64: {hex2b64(cypher)}\n")

#base64, hex etc. = encoding
#rsa, aes etc. = cryptography

#To convert from hex to base64 -->
#- convert to binary
#- divide to groups of 6 (1+2+4+8+16+32)
#- Convert using base64 indexing table
#if padding use =

