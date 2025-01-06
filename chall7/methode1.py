from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

key = "YELLOW SUBMARINE"
file = "file7.txt"
mode = AES.MODE_ECB
#Charger et décoder les données en base64
#Initialiser ECB
#Déchiffrer chaque bloque
#Supprimer padding
def aes_decrypt(file, key, mode):
    key = key.encode('utf-8')
    decypher = AES.new(key, mode)
    with open(file, "r") as file:
        data = file.read()
        data = base64.b64decode(data)
        plain = unpad(decypher.decrypt(data), 16)
    return plain

print(aes_decrypt(file, key, mode))