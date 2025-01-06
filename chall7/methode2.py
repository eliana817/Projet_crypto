from Crypto.Cipher import AES
import base64


key = b"YELLOW SUBMARINE"

with open("exo7.txt", 'r') as file:
    ciph = base64.b64decode(file.read())

#print(ciph)
aes = AES.new(key, AES.MODE_ECB)
result = aes.decrypt(ciph)

print(result)