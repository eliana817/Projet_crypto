import binascii

text = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
key = "ICE"

result = ""

for k in range(0, len(text), len(key)):
    for i in range(len(key)):
        if k+i <= len(text) - 1: #so that it doesn't go out of range
            result += ''.join(hex(ord(key[i]) ^ ord(text[k+i]))[2:]) #[2:] is to not display 0x 

print(result)