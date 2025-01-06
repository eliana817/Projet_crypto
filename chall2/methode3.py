def xor(text1, text2):
    bytes1 = bytes.fromhex(text1)
    bytes2 = bytes.fromhex(text2)

    if len(bytes1) == len(bytes2):
        x = bytes(a ^ b for a, b in zip(bytes1, bytes2))
        return x.hex()

    else:
        return 'Not the same length'

text = '1c0111001f010100061a024b53535009181c'
key = '686974207468652062756c6c277320657965'
print(xor(text, key))
print('\n')