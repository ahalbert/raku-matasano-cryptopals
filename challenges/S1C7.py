from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

backend = default_backend()

def decrypt_aes_128_ecb(ctxt, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
    # would need some padding stripping actually (we'll see padding later)
    message = decrypted_data
    return message

if __name__ == "main":
    with open("7.txt") as file:
        data = file.read()
        print(type(b64decode(data)))
        
    print(decrypt_aes_128_ecb(
            ctxt = data,
            key="YELLOW SUBMARINE"
        ).decode())
