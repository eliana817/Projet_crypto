from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii

#PART 1: encrypt to the AES mode provided
def generate_key(length):
    return get_random_bytes(length)

def aes_encrypt(text, key_length, mode):

    key = generate_key(key_length)
    cipher = AES.new(key, mode)
    encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
    result = binascii.hexlify(encrypted)

    return result

mode = AES.MODE_CBC

print(aes_encrypt("hello world", 16, mode))

##PART2: To detect AES Mode (inspired by function created in challenge 8)
def detect_aes(text) -> None:

    blocks = [text[i:i+32] for i in range(0, len(text), 32)]
    unique_blocks = len(set(blocks))
    total_blocks = len(blocks)
    repetitions = total_blocks - unique_blocks

    if repetitions > 0: #si il y a des répétions, ça pourrait etre ECB
        print("Encrypted with ECB")
    else:
        print("Encrypted using CBC")

detect_aes('debafb4d44dcd2367ab05c018ca9598f')


