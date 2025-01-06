input1 = '1c0111001f010100061a024b53535009181c'
input2 = '686974207468652062756c6c277320657965'

#Methode 2
def xor(input1, input2):
    """
    Function xors 2 hex values.
    
    - input1, input2: The 2 hexadecimal values to xor

    Returns: the result of the operation
    """
    if len(input1) > len(input2): #to set the same size for both hex
        length = len(input1) * 4
    else:
        length = len(input2) * 4

    bin1 = bin(int(input1, 16))[2:].zfill(length)
    bin2 = bin(int(input2, 16))[2:].zfill(length)
    result = ""

    for k in range(len(bin2)):
        if int(bin1[k]) ^ int(bin2[k]) == False:
            result += "0"
        else:
            result += "1"

    return hex(int(result, 2))

print("Methode 2: \n", xor(input1, input2))
