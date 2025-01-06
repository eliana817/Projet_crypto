from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import binascii
from cryptopal.chall7.methode1 import aes_decrypt

key = "YELLOW SUBMARINE"
key = key.encode('utf-8')
decypher = AES.new(key, AES.MODE_CBC)
plain = ''
"""
Méthode 2 utiliser la fonction du challenge 7:
Diviser le texte en bloques
Xor avec le bloque chiffré precedent (avec la fonction)
--> AES
"""
#Charger et décoder les données en base64
#Initialiser ECB
#Déchiffrer chaque bloque
#Supprimer padding

with open("file10.txt", "r") as file:
    data = file.read()
    data = base64.b64decode(data)
    plain = unpad(decypher.decrypt(data), 16)

print(plain)


"""def cbc(file):
    data = open(file).read()

    bytes = binascii.hexlify(data)
    for byte in bytes:
        print(byte, "###################\n")

cbc("file10.txt")"""