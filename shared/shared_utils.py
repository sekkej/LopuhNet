import os
# import socket
# import random
# import hashlib
# import time
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_der_private_key
from .kyber_py.ml_kem import ML_KEM_1024
from .dilithium_py.ml_dsa import ML_DSA_87
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad

# Replaced with ChaCha20Poly1305 (in a bundle including ML-KEM)
# class AESCipher:
#     """AES Cipher"""

#     # @staticmethod
#     # def encrypt(data: str|bytes, key: bytes) -> bytes:
#     #     iv = os.urandom(16)
#     #     cipher = AES.new(key, AES.MODE_CBC, iv)
#     #     rdata = data
#     #     if isinstance(data, str):
#     #         rdata = data.encode()
#     #     ciphertext = cipher.encrypt(pad(rdata, AES.block_size))
#     #     return iv + ciphertext

#     # @staticmethod
#     # def decrypt(ciphertext: bytes, key: bytes) -> bytes:
#     #     iv = ciphertext[:16]
#     #     cipher = AES.new(key, AES.MODE_CBC, iv)
#     #     data = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
#     #     return data
#     @staticmethod
#     def _pad(data: bytes):
#         padder = PKCS7(128).padder()
#         padded_data = padder.update(data)
#         padded_data += padder.finalize()
#         return padded_data
    
#     @staticmethod
#     def _unpad(padded_data: bytes):
#         unpadder = PKCS7(128).unpadder()
#         data = unpadder.update(padded_data)
#         data += unpadder.finalize()
#         return data

#     @staticmethod
#     def encrypt(
#         data: bytes,
#         key: bytes = os.urandom(32),
#         iv: bytes = os.urandom(16),
#     ) -> bytes:
#         cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
#         encryptor = cipher.encryptor()
#         enc = encryptor.update(AESCipher._pad(data)) + encryptor.finalize()
#         return iv + enc
    
#     @staticmethod
#     def decrypt(
#         data: bytes,
#         key: bytes = os.urandom(32),
#         iv: bytes = os.urandom(16)
#     ) -> bytes:
#         iv = data[:16]
#         cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
#         decryptor = cipher.decryptor()
#         dec = decryptor.update(data[16:]) + decryptor.finalize()
#         return AESCipher._unpad(dec)

# Deprecated
# class HFAES:
#     """
#     ## Hash-Flooded AES
#     Created by sekkej especially for LopuhNet.
#     Works like this:
#         1. Encrypts data with AES (in CFB mode)
#         2. Padds crypted data randomly with random bytes from both sides
#         3. Hashes the starting index (HSI) and data length (HDL) with MD5
#         4. HSI adds to the start of crypted data, HDL to the end.
#     When decrypting, we simply brute both hashes and find data we need.
#     Works perfectly because there's recommended factor of flooding!
#     """
#     @staticmethod
#     def encrypt(
#         data: bytes,
#         key: bytes = os.urandom(16),
#         floodfactor: int = 9
#     ) -> bytes:
#         aesc = AESCipher.encrypt(data, key)

#         hsi = random.randint(1, 2**floodfactor)
#         hdl = len(aesc)
#         faesc = os.urandom(hsi) + aesc + os.urandom(random.randint(1, 2**floodfactor))

#         hhsi = hashlib.md5(key + str(hsi).encode()).digest()
#         hhdl = hashlib.md5(key + str(hdl).encode()).digest()

#         result = hhsi + faesc + hhdl
#         return result

#     @staticmethod
#     def decrypt(
#         data: bytes,
#         key: bytes = os.urandom(16),
#         floodfactor: int = 9
#     ) -> bytes:
#         hhsi = data[:16]
#         hhdl = data[-16:]
#         hsi = 0
#         hdl = 0

#         for i in range(2**floodfactor+1):
#             dec = key + str(i).encode()
#             if hhsi == hashlib.md5(dec).digest():
#                 hsi = i
#         for i in range(655):
#             dec = key + str(i).encode()
#             if hhdl == hashlib.md5(dec).digest():
#                 print('FUCKDEC1', dec)
#                 print('FUCKDEC2', i)
#                 print('FUCKDEC3', hashlib.md5(dec).digest())
#                 hdl = i
        
#         aesc = data[hsi+16:][:hdl]

#         return AESCipher.decrypt(aesc, key)

# Replaced with ML-KEM
# class ECDH:
#     """Elliptic Curve Diffie-Hellman key-exchanging algorithm"""

#     def __init__(self):
#         self.private  = ec.generate_private_key(ec.SECP256R1())
#         self.__public = self.private.public_key()
    
#     @property
#     def public_key(self) -> bytes:
#         return self.__public.public_bytes(
#             encoding=serialization.Encoding.DER,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         )

#     def shared_key(self, peer_public: bytes, purpose: str) -> bytes:
#         peer_public = load_der_public_key(peer_public)
#         shared_key = self.private.exchange(ec.ECDH(), peer_public)
#         derived_key = HKDF(
#             algorithm=hashes.SHA256(),
#             length=32,
#             salt=None,
#             info=purpose.encode(),
#         ).derive(shared_key)
#         return derived_key

# class SocketUtils:
#     @staticmethod
#     def compare_addrs(addr1: tuple[str, int], addr2: tuple[str, int]) -> bool:
#         """Compare two addresses

#         Args:
#             addr1 (tuple[str, int]): first IP and port
#             addr2 (tuple[str, int]): second IP and port

#         Returns:
#             bool: are they the same
#         """
#         true_addr1 = addr1[0].replace('127.0.0.1', 'localhost').replace('0.0.0.0', 'localhost')
#         true_addr2 = addr2[0].replace('127.0.0.1', 'localhost').replace('0.0.0.0', 'localhost')
#         return true_addr1 == true_addr2 and addr1[1] == addr2[1]

# Replaced with ML-DSA
# class PacketDNA:
#     """
#     Utility allows to sign packets' data with RSA encryption
#     Makes not possible to fake auth packet
#     """
#     def __init__(self, password: bytes, public_key: bytes = None, private_key: bytes = None):
#         self.password = password
#         if private_key is not None and public_key is not None:
#             self.__public = load_der_public_key(public_key)
#             self.__private = load_der_private_key(private_key, self.password)
#         else:
#             self.__private = rsa.generate_private_key(
#                 public_exponent=65537,
#                 key_size=2048
#             )
#             self.__public = self.__private.public_key()
    
#     @property
#     def public(self) -> bytes:
#         return self.__public.public_bytes(
#             encoding=serialization.Encoding.DER,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         )

#     @property
#     def private(self) -> bytes:
#         return self.__private.private_bytes(
#             encoding=serialization.Encoding.DER,
#             format=serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=serialization.BestAvailableEncryption(self.password)
#         )
    
#     def sign(self, packet_data: bytes):
#         return self.__private.sign(
#             packet_data,
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256()
#         )
    
#     @staticmethod
#     def verify(data: bytes, signature: bytes, peer_public: bytes):
#         peer_public = load_der_public_key(peer_public)
#         try:
#             peer_public.verify(
#                 signature,
#                 data,
#                 padding.PSS(
#                     mgf=padding.MGF1(hashes.SHA256()),
#                     salt_length=padding.PSS.MAX_LENGTH
#                 ),
#                 hashes.SHA256()
#             )
#             return True
#         except:
#             return False
    
#     # Inner class of Exception
#     class PacketDNAException(BaseException):
#         """
#         Exception of PacketDNA
#         """
#         def __init__(self, message, *args: object):
#             """
#             Exception of PacketDNA
#             """
#             super().__init__(message, *args)

class PacketDSA:
    def __init__(self, public_key: bytes = None, private_key: bytes = None):
        if private_key is not None and public_key is not None:
            self.public = public_key
            self.private = private_key
        else:
            self.public, self.private = ML_DSA_87.keygen()
    
    def sign(self, packet_data: bytes):
        return ML_DSA_87.sign(self.private, packet_data)
    
    @staticmethod
    def verify(data: bytes, signature: bytes, peer_public: bytes):
        return ML_DSA_87.verify(peer_public, data, signature)

# Deprecated implementation
# class CHAKEMDSA:
    # """Encryption based on ML-KEM and ChaCha20Poly1305 and signing with ML-DSA"""
    # def __init__(self):
    #     self.sign_public, self.sign_private = ML_DSA_87.keygen()
    #     self.encryption_key, self.private_key = ML_KEM_1024.keygen()
    #     self.encryption_key : bytes
    #     self.private_key : bytes

#     def _get_derived_eckey(self, peer_encryption_key: bytes, purpose: bytes):
#         shared_secret, pub_key = ML_KEM_1024.encaps(peer_encryption_key)
        
#         # Derive the same encryption key
#         derived_key = HKDF(
#             algorithm=hashes.SHA384(),
#             length=32,
#             salt=None,
#             info=purpose,
#         ).derive(shared_secret)

#         return derived_key, pub_key

#     def _get_derived_dckey(self, peer_public_key: bytes, purpose: bytes):
#         shared_secret = ML_KEM_1024.decaps(self.private_key, peer_public_key)
        
#         # Derive the same encryption key
#         derived_key = HKDF(
#             algorithm=hashes.SHA384(),
#             length=32,
#             salt=None,
#             info=purpose,
#         ).derive(shared_secret)

#         return derived_key

#     def encrypt_data(self, data: bytes, peer_encryption_key: bytes, purpose: bytes) -> tuple[bytes, bytes, bytes]:
#         derived_key, public_key = self._get_derived_eckey(peer_encryption_key, purpose)

#         chacha = ChaCha20Poly1305(derived_key)
#         nonce = os.urandom(12)
#         encrypted_data = chacha.encrypt(nonce, data)
        
#         return encrypted_data, public_key, nonce

#     def decrypt_data(self, data: bytes, public_key: bytes, nonce: bytes, purpose: bytes) -> bytes:
#         derived_key = self._get_derived_dckey(public_key, purpose)

#         chacha = ChaCha20Poly1305(derived_key)
#         decrypted_data = chacha.decrypt(nonce, data)
        
#         return decrypted_data
    
#     def get_signature(self, data: bytes) -> bytes:
#         return ML_DSA_87.sign(self.sign_private, data)
    
#     @staticmethod
#     def verify_signature(data: bytes, peer_sign_public: bytes, signature: bytes):
#         return ML_DSA_87.verify(peer_sign_public, data, signature)
    
#     def encipher(self, data: bytes, peer_encryption_key: bytes, purpose: bytes) -> tuple[bytes, bytes, bytes, bytes]:
#         """Encrypts and signs the data. Returns **all you need to send** to another peer.

#         Args:
#             data (bytes): the data's being sent
#             peer_encryption_key (bytes): pre-agreed encryption key, received from peer whom we send
#             purpose (bytes): purpose of the cipher (e.g.: b'debug-client1-client2')

#         Returns:
#             tuple[bytes]: [\n
#             encrypted data\n
#             public key\n
#             nonce\n
#             signature of the data\n
#             your public key used to sign data
# \n          ]
#         """
#         encrypted = self.encrypt_data(data, peer_encryption_key, purpose)
#         signature = self.get_signature(encrypted[0])
#         return (*encrypted, signature, self.sign_public)
    
#     def decipher(self, data: bytes, peer_public_key: bytes, nonce: bytes, purpose: bytes, signature: bytes, peer_sign_public: bytes):
#         if not CHAKEMDSA.verify_signature(data, peer_sign_public, signature):
#             raise RuntimeError("Signature verification failed!")
#         return self.decrypt_data(data, peer_public_key, nonce, purpose)

class CHAKEM:
    """Encryption based on ML-KEM and ChaCha20Poly1305 and signing with ML-DSA"""
    @staticmethod
    def generate_keys() -> tuple[bytes, bytes]:
        return ML_KEM_1024.keygen()

    @staticmethod
    def encrypt(
            data: bytes,
            recipient_public_key: bytes,
            # own_private_signkey: bytes,
            purpose: bytes
        ) -> tuple[bytes, bytes, bytes]:
        shared_secret, ciphertext = ML_KEM_1024.encaps(recipient_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=purpose,
        ).derive(shared_secret)

        nonce = os.urandom(12)
        encrypted = ChaCha20Poly1305(derived_key) \
                        .encrypt(nonce, data, associated_data=None)
        
        # signature = ML_DSA_87.sign(own_private_signkey, encrypted)
        
        return encrypted, ciphertext, nonce #, signature
    
    @staticmethod
    def decrypt(
            data: bytes,
            own_private_key: bytes,
            cipher_text: bytes,
            nonce: bytes,
            # sender_public_signkey: bytes,
            # signature: bytes,
            purpose: bytes
        ) -> bytes:
        # if not ML_DSA_87.verify(sender_public_signkey, data, signature):
        #     raise RuntimeError("Data verification by signature has failed!")

        shared_secret = ML_KEM_1024.decaps(own_private_key, cipher_text)
        derived_key = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=purpose,
        ).derive(shared_secret)

        decrypted = ChaCha20Poly1305(derived_key) \
                        .decrypt(nonce, data, associated_data=None)
        
        return decrypted

# enckey, deckey = CHAKEM.generate_keys()
# enc = CHAKEM.encrypt(b'test', enckey, b'Purpose!')
# dec = CHAKEM.decrypt(enc[0], deckey, enc[1], enc[2], b'Purpose!')
# print(enc)
# print(dec)
# c1 = PacketDSA()
# c2 = PacketDSA()
# signature = c1.sign(enc[0])
# print(c2.verify(enc[0], signature, c1.public))

# c1pdna = PacketDNA(b'rrrk1488')
# c2pdna = PacketDNA(b'mrbeasttop')

# signature = c1pdna.sign(b'Hello, world! (sent from: c1)')
# print(signature)

# v1 = c2pdna.verify(b'Hello, world! (sent from: c1)', signature, c1pdna.public)
# print(v1)
# v2 = c2pdna.verify(b'Hello, world! (sent from: c1488)', signature, c1pdna.public)
# print(v2)


# key = os.urandom(32)
# enc = AESCipher.encrypt(b'hello', key)
# dec = AESCipher.decrypt(enc, key)
# print(enc)
# print(dec)


# key = os.urandom(32)
# enc = HFAES.encrypt('pidor'*16, key)
# print(enc)
# dec = HFAES.decrypt(enc, key)
# print(dec)

# from kyber_py.ml_kem import ML_KEM_1024
# from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# def generate_keys():
#     encryption_key, private_key = ML_KEM_1024.keygen()
#     return encryption_key, private_key

# def get_derived_eckey(encryption_key: bytes, purpose: bytes):
#     shared_secret, pub_key = ML_KEM_1024.encaps(encryption_key)
    
#     # Derive the same encryption key
#     derived_key = HKDF(
#         algorithm=hashes.SHA384(),
#         length=32,
#         salt=None,
#         info=purpose,
#     ).derive(shared_secret)

#     return derived_key, pub_key

# def get_derived_dckey(private_key: bytes, public_key: bytes, purpose: bytes):
#     shared_secret = ML_KEM_1024.decaps(private_key, public_key)
    
#     # Derive the same encryption key
#     derived_key = HKDF(
#         algorithm=hashes.SHA384(),
#         length=32,
#         salt=None,
#         info=purpose,
#     ).derive(shared_secret)

#     return derived_key

# def encrypt_data(data: bytes, encryption_key: bytes, purpose: bytes) -> tuple[bytes, bytes, bytes]:
#     derived_key, public_key = get_derived_eckey(encryption_key, purpose)

#     chacha = ChaCha20Poly1305(derived_key)
#     nonce = os.urandom(12)
#     encrypted_data = chacha.encrypt(nonce, data)
    
#     return encrypted_data, public_key, nonce

# def decrypt_data(data: bytes, public_key: bytes, nonce: bytes, private_key: bytes, purpose: bytes) -> bytes:
#     derived_key = get_derived_dckey(private_key, public_key, purpose)

#     chacha = ChaCha20Poly1305(derived_key)
#     decrypted_data = chacha.decrypt(nonce, data)
    
#     return decrypted_data

# def stats_aes():
#     print('Original data:', data)
#     print('Purpose:', purpose)
#     print()

#     print('AES + ECDH Stats:')
#     keygen_start_time = time.time_ns()
#     ecdh = ECDH()
#     key = ecdh.shared_key(ecdh.public_key, purpose.decode())
#     keygen_time = time.time_ns() - keygen_start_time

#     encryption_start_time = time.time_ns()
#     enc = AESCipher.encrypt(data, key)
#     encryption_time = time.time_ns() - encryption_start_time
#     print('Encrypted data:', enc)

#     decryption_start_time = time.time_ns()
#     dec = AESCipher.decrypt(enc, key)
#     decryption_time = time.time_ns() - decryption_start_time
#     print('Decrypted data:', dec)

#     print()

#     print('Key-Generation time:', keygen_time//1_000_000, 'ms')
#     print('Encryption time:', encryption_time//1_000_000, 'ms')
#     print('Decryption time:', decryption_time//1_000_000, 'ms')

#     print()

#     print('Total time of code execution:', (keygen_time + encryption_time + decryption_time)//1_000_000, 'ms')

#     print()

#     print('Approximate number of bytes used for key-exchange:', len(key))
#     print('Approximate number of bytes used for encrypted data:', len(enc))
#     print('Approximate number of bytes used for decrypted data:', len(dec))
#     print('Total approximate number of bytes used:', len(key) + len(enc) + len(dec))

# def stats_mlkem():
#     print('Original data:', data)
#     print('Purpose:', purpose)
#     print()

#     print('ML-KEM + ChaCha20Poly1305 Stats:')
#     # [S->R] Sender sends Key-Exchange (via ML-KEM) request
#     # Receiver generates key-pair
#     keygen_start_time = time.time_ns()
#     encryption_key, private_key = generate_keys()
#     keygen_time = time.time_ns() - keygen_start_time
#     # [R->S] And sends back the encryption key

#     # [S->R] Sender encrypts data, knowing encryption key and sends (encrypted, public, nonce) to the Receiver
#     encryption_start_time = time.time_ns()
#     encrypted, public, nonce = encrypt_data(data, encryption_key, purpose)
#     encryption_time = time.time_ns() - encryption_start_time
#     print('Encrypted data:', encrypted)

#     # Receiver decrypts data, knowing the encrypted data, public key, nonce and private key.
#     decryption_start_time = time.time_ns()
#     decrypted = decrypt_data(encrypted, public, nonce, private_key, purpose)
#     decryption_time = time.time_ns() - decryption_start_time
#     print('Decrypted data:', decrypted)

#     print()

#     print('Key-Generation time:', keygen_time//1_000_000, 'ms')
#     print('Encryption time:', encryption_time//1_000_000, 'ms')
#     print('Decryption time:', decryption_time//1_000_000, 'ms')

#     print()

#     print('Total time of code execution:', (keygen_time + encryption_time + decryption_time)//1_000_000, 'ms')

#     print()

#     print('Approximate number of bytes used for key-exchange:', len(encryption_key) + len(private_key))
#     print('Approximate number of bytes used for encrypted data:', len(encryption_key) + len(nonce) + len(encrypted) + len(public))
#     print('Approximate number of bytes used for decrypted data:', len(encryption_key) + len(private_key) + len(nonce) + len(encrypted) + len(public))
#     print('Total approximate number of bytes used:', len(encryption_key) + len(private_key) + len(nonce) + len(encrypted) + len(public))

# data = 'Xaaxaxxaxaxaxaxaxx'.encode()
# purpose = b'Average Poland discussion.'

# # stats_aes()
# # stats_mlkem()

# c1 = CHAKEMDSA()
# c2 = CHAKEMDSA()

# msg = c1.encipher('test'.encode(), c2.encryption_key, purpose)
# encrypted, public, nonce, signature, sign_public = msg
# print(encrypted)
# total_bytes_to_transmit = len(b''.join(msg))
# print(round(total_bytes_to_transmit / 1024, 2), 'KB')

# print(c2.decipher(encrypted, public, nonce, purpose, signature, sign_public))

# # print(c2.decipher(encrypted, public, nonce, purpose, signature, sign_public))

# msg = c2.encipher(b'Acknowledged. We attack Poland at dawn.', c1.encryption_key, purpose)
# encrypted, public, nonce, signature, sign_public = msg
# print(encrypted)
# total_bytes_to_transmit = len(b''.join(msg))
# print(round(total_bytes_to_transmit / 1024, 2), 'KB')

# print(c1.decipher(encrypted, public, nonce, purpose, signature, sign_public))


# encrypted, public, nonce = c1.encrypt_data(b'Hi Client2!', c2.encryption_key, purpose)
# print(encrypted)
# decrypted = c2.decrypt_data(encrypted, public, nonce, purpose)
# print(decrypted)

# encrypted, public, nonce = c2.encrypt_data(b'Yeah, nice to meet you Client1!', c1.encryption_key, purpose)
# print(encrypted)
# decrypted = c1.decrypt_data(encrypted, public, nonce, purpose)
# print(decrypted)

# print(len(c1.private_key))