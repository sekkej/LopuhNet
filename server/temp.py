from diffiehellman import DiffieHellman

# automatically generate two key pairs
dh1 = DiffieHellman()
dh2 = DiffieHellman()
...
dh3 = DiffieHellman()

# get both public keys
dh1_public = dh1.get_public_key()
dh2_public = dh2.get_public_key()
...
dh3_public = dh3.get_public_key()

# generate shared key based on the other side's public key
dh1_shared_w2 = dh1.generate_shared_key(dh2_public)
dh1_shared_w3 = dh1.generate_shared_key(dh3_public)
...

dh2_shared = dh2.generate_shared_key(dh1_public)
dh3_shared = dh3.generate_shared_key(dh1_public)
...

# the shared keys should be equal
assert dh1_shared_w2 == dh2_shared
print("dh1 == dh2")

assert dh1_shared_w3 == dh3_shared
print("dh1 == dh3")

print(dh3_shared)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def derive_key(shared_secret, key_length, salt=None):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        info=b'encrypted'
    )
    return hkdf.derive(shared_secret)

# Assuming 'dh_key' is your Diffie-Hellman shared secret
derived_key = derive_key(dh3_shared, 32)  # for AES-256

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

def encrypt_aes(key, plaintext):
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.ECB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_aes(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.ECB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Usage
ciphertext = encrypt_aes(derived_key, b"")
plaintext = decrypt_aes(derived_key, ciphertext)