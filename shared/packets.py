import os
import base64
import brotli
import xxhash
import time
import json
from .basic_types import Packet, User, ServerAccount
# from .shared_utils import AESCipher, PacketDNA
from .shared_utils import CHAKEM, PacketDSA
from .eventflags import EventFlags

class TransmissionRequest(Packet):
    pId = 0x001
    pName = 'TransmissionRequest'

    def __init__(self,
                 sender: User,
                 recipient: User,
                 event: 'Event' = None,
                 eid: str = None,
                 edata: str = None,
                 data = None
            ):
        super().__init__(sender, ServerAccount(), {
            'eid': eid or (event.eid if event else None),
            'data': edata or (base64.b64encode(bytes(event)).decode() if event else None),
            'recipient': recipient.__dict__
        })
    
    def __bytes__(self):
        return self.pId.to_bytes(4, 'big') + super().__bytes__()
    
    @classmethod
    def from_bytes(cls, data):
        pId = int.from_bytes(data[:4], 'big')
        if pId != cls.pId:
            raise RuntimeError(f"Invalid packet id! Expected: {cls.pId}, got {pId}")
        extracted_data = Packet.from_bytes(data[4:]).data
        return super().from_bytes(
            data[4:],
            eid=extracted_data['eid'],
            edata=extracted_data['data']
        )

class TransmissionResult(Packet):
    pId = 0x002
    pName = 'TransmissionResult'

    def __init__(self,
                 recipient: User,
                 event_id: str = None, 
                 result: bool = None, 
                 sender: None = None,
                 data = None
            ):
        super().__init__(ServerAccount(), recipient, {
            'eid': event_id,
            'result': result
        })
    
    def __bytes__(self):
        return self.pId.to_bytes(4, 'big') + super().__bytes__()
    
    @classmethod
    def from_bytes(cls, data):
        pId = int.from_bytes(data[:4], 'big')
        if pId != cls.pId:
            raise RuntimeError(f"Invalid packet id! Expected: {cls.pId}, got {pId}")
        return super().from_bytes(data[4:])

class SecurePacket(Packet):
    def __init__(self,
                sender_packet_dsa: PacketDSA,
                recipient_public_key: bytes,
                purpose_info: bytes,
                sender: User,
                recipient: User,
                data: dict
            ):
        super().__init__(sender, recipient, data)
        self.recipient_public_key = recipient_public_key
        self.purpose_info = purpose_info
        self.pdsa = sender_packet_dsa
    
    def __bytes__(self):
        encrypted = CHAKEM.encrypt(
            brotli.compress(super().__bytes__()),
            self.recipient_public_key,
            self.purpose_info
        )

        if self.pdsa is not None:
            signature = base64.b64encode(self.pdsa.sign(encrypted[0])).decode()
        else:
            signature = None
        
        return self.pId.to_bytes(4, 'big') + json.dumps({
            'encrypted': base64.b64encode(encrypted[0]).decode(),
            'ciphertext': base64.b64encode(encrypted[1]).decode(),
            'nonce': base64.b64encode(encrypted[2]).decode(),
            'signature': signature
        }, ensure_ascii=False).encode()

    @classmethod
    def from_bytes(cls,
                    data: bytes,
                    own_private_key: bytes,
                    purpose_info: bytes,
                    peer_sign_public: bytes = None,
                    _verify_signature: bool = True,
                ):
        jsondata = json.loads(data[4:])
        pId = int.from_bytes(data[:4], 'big')
        encdata = base64.b64decode(jsondata['encrypted'])
        cipher_text = base64.b64decode(jsondata['ciphertext'])
        nonce = base64.b64decode(jsondata['nonce'])
        signed = jsondata['signature'] is not None
        if signed:
            signature = base64.b64decode(jsondata['signature'])

        if _verify_signature and signed and peer_sign_public is not None \
             and not PacketDSA.verify(encdata, signature, peer_sign_public):
            raise RuntimeError("PacketDSA SecurePacket verification failure.") # Must be catched.
        
        decrypted = super().from_bytes(brotli.decompress(
            CHAKEM.decrypt(
                encdata,
                own_private_key,
                cipher_text,
                nonce,
                purpose_info
            )),
            recipient_public_key=None,
            purpose_info=None,
            sender_packet_dsa=None
        )

        if _verify_signature and signed and peer_sign_public is None:
            peer_sign_public = base64.b64decode(decrypted.sender.public_signkey)
            if not PacketDSA.verify(encdata, signature, peer_sign_public):
                raise RuntimeError("PacketDSA SecurePacket verification failure.") # Must be catched.

        decrypted.pId = pId
        return decrypted

class Registration(SecurePacket):
    pId = 0x010
    pName = 'Registration'

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: list[User] = None,
            user: User = None,
            data: None = None # Used while decoding
            ):
        self.user = user
        super().__init__(
            sender_packet_dsa,
            recipient_public_key,
            b'lopuhnet-auth',
            sender,
            recipient,
            {
                'pId':   0x010,
                'pName': 'Registration',
                'user': self.user
            }
        )

class RegistrationConfirmationRequest(SecurePacket):
    pId = 0x011
    pName = 'RegistrationConfirmationRequest'

    def __init__(self,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: list[User] = None,
            captcha_image: str = None,
            proof_of_work_params: dict = None,
            data: None = None # Used while decoding
            ):
        self.captcha_image = captcha_image
        self.proof_of_work_params = proof_of_work_params
        super().__init__(
            None,
            recipient_public_key,
            b'lopuhnet-auth',
            sender,
            recipient,
            {
                'pId':   0x011,
                'pName': 'RegistrationConfirmationRequest',
                'captcha_image': self.captcha_image,
                'proof_of_work_params': self.proof_of_work_params
            }
        )

class RegistrationConfirmation(SecurePacket):
    pId = 0x012
    pName = 'RegistrationConfirmation'

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: list[User] = None,
            captcha_solution: str = None,
            proof_of_work_solution: dict = None,
            data: None = None # Used while decoding
            ):
        self.captcha_solution = captcha_solution
        self.proof_of_work_solution = proof_of_work_solution
        super().__init__(
            sender_packet_dsa,
            recipient_public_key,
            b'lopuhnet-auth',
            sender,
            recipient,
            {
                'pId':   0x012,
                'pName': 'RegistrationConfirmation',
                'captcha_solution': self.captcha_solution,
                'proof_of_work_solution': self.proof_of_work_solution
            }
        )

class RegistrationResult(SecurePacket):
    pId = 0x013
    pName = 'RegistrationResult'

    def __init__(self,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: list[User] = None,
            message: str = None,
            data: None = None # Used while decoding
            ):
        self.message = message
        super().__init__(None, recipient_public_key, b'lopuhnet-auth', sender, recipient, {
            'pId':   0x013,
            'pName': 'RegistrationResult',
            'message': self.message
        })

class Authentication(SecurePacket):
    pId = 0x014
    pName = 'Authentication'

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: list[User] = None,
            user: User = None,
            data: None = None # Used while decoding
            ):
        self.user = user
        super().__init__(
            sender_packet_dsa,
            recipient_public_key,
            b'lopuhnet-auth',
            sender,
            recipient,
            {
                'pId':   0x014,
                'pName': 'Authentication',
                'user': self.user
            }
        )

class AuthenticationResult(SecurePacket):
    pId = 0x015
    pName = 'AuthenticationResult'

    def __init__(self,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: list[User] = None,
            message: str = None,
            data: None = None # Used while decoding
            ):
        self.message = message
        super().__init__(None, recipient_public_key, b'lopuhnet-auth', sender, recipient, {
            'pId':   0x015,
            'pName': 'AuthenticationResult',
            'message': self.message
        })

class Event(SecurePacket):
    pId = -1
    pName = ''
    flags = 0

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User,
            recipient: User,
            data: None = None, # Used while decoding
            purpose_info: bytes = None, # Ignored
            ):
        self.eid = xxhash.xxh128(f'{time.time_ns()}').hexdigest()
        super().__init__(
            sender_packet_dsa,
            recipient_public_key, 
            b'lopuhnet-event', 
            sender,
            recipient,
            {
                'eid': self.eid,
                **data
            }
        )

    @classmethod
    def from_bytes(cls,
                    data: bytes,
                    own_private_key: bytes,
                    peer_sign_public: bytes = None,
                    _verify_signature: bool = True
                ):
        return super().from_bytes(
            data,
            own_private_key,
            b'lopuhnet-event',
            peer_sign_public,
            _verify_signature
        )

class FriendRequest(Event):
    pId   = 0x100
    pName = 'FriendRequest'
    flags = 0 + EventFlags.DISPOSABLE

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: User = None,
            user: str | User = None,
            data: None = None # Used while decoding
            ):
        self.user = user
        super().__init__(
            sender_packet_dsa,
            recipient_public_key,
            sender,
            recipient,
            {
                'pId':   self.pId,
                'pName': self.pName,
                'user': self.user
            }
        )

class FriendRequestResult(Event):
    pId   = 0x101
    pName = 'FriendRequestResult'
    flags = 0 + EventFlags.DISPOSABLE

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: User = None,
            fr_eid: str = None, # EventID of FriendRequest
            result: tuple = None,
            data: None = None # Used while decoding
            ):
        self.fr_eid = fr_eid
        self.result = result
        super().__init__(
            sender_packet_dsa,
            recipient_public_key,
            sender,
            recipient,
            {
                'pId':   self.pId,
                'pName': self.pName,
                'request_eid': self.fr_eid,
                'result': self.result
            }
        )

# Deprecated
# class LUP(Packet):
#     """
#     # Lopuh UDP Packet
#     Standard packet for communication between two users over insecure UDP channel.
#     Splits bytes of the child packet of SecurePacket into enumerated chunks which represents the order SecurePacket data chunks.
#     Gives ID for the current order of chunks based on XXHash of current time and packet data.
#     Data encoded to Base64 because LUP is a packet type and data needs to be JSON type.
#     Doesn't have anything special or vulnerable in . All sensetive data encrypted in the SecurePacket itself.
#     """

#     def __init__(self,
#                 sender: User,
#                 recipient: list[User],
#                 order_id: str = None,
#                 index: int = None,
#                 length: int = None, 
#                 signature: str = None,
#                 ciphertext: str = None,
#                 nonce: str = None,
#                 purpose_info: str = None,
#                 data: str = None
#             ) -> None:
#         self.order_id = order_id
#         """ID of the order"""
#         self.index = index
#         """Index of packet relative to the order"""
#         self.length = length
#         """Length of data (measured by maximum index -> len(chunks))"""
#         self.signature = signature
#         """Signature for the packet to verify with PacketDSA"""
#         self.ciphertext = ciphertext
#         """Signature for the packet to verify with PacketDSA"""
#         self.nonce = nonce
#         """Signature for the packet to verify with PacketDSA"""
#         self.purpose_info = purpose_info
#         """Signature for the packet to verify with PacketDSA"""
#         self.data_b64 = data
#         """Base64 encoded bytes of chunk of SecurePacket's data"""

#         super().__init__(sender, recipient, {
#             'order_id': self.order_id,
#             'index': self.index,
#             'length': self.length,
#             'signature': self.signature,
#             'ciphertext': self.ciphertext,
#             'nonce': self.nonce,
#             'purpose_info': self.purpose_info,
#             'data': self.data_b64
#         })
    
#     @staticmethod
#     def generate_chunks(
#                 packet: SecurePacket,
#                 packet_dsa: PacketDSA,
#             ) -> list['LUP']:
#         """Generates a list of LUPs to send each one"""
#         n = 777 # chunk size
#         data = bytes(packet)
#         order_id = xxhash.xxh128(f'{time.time_ns()}{data}').hexdigest()

#         metadp = json.loads(data.decode())
#         ciphertext = metadp['ciphertext']
#         nonce = metadp['nonce']
        
#         return [
#             LUP(
#                 packet.sender,
#                 packet.recipient,
#                 order_id,
#                 idx,
#                 len(range(0, len(data), n)),
#                 base64.b64encode(packet_dsa.sign(data)).decode(),
#                 ciphertext,
#                 nonce,
#                 base64.b64encode(packet.purpose_info).decode(),
#                 base64.b64encode(data[i:i+n]).decode()
#             )
#             for idx, i in enumerate(range(0, len(data), n))
#         ]

# user = User('Server', "Server", "Server", "server", "", "l.n.e.t", '00000000000000000000000000000000')

# c1public, c1private = CHAKEM.generate_keys()
# c2public, c2private = CHAKEM.generate_keys()
# pdsa1 = PacketDSA()
# pdsa2 = PacketDSA()

# ev = MsgCreated(
#     c2public,
#     sender=user,
#     recipient=[user],
#     message='Ku-ku, my darling!'
# )
# print(ev.data)
# bev = bytes(ev)
# print(bev, len(bev))

# print()

# lupev = LUP.generate_chunks(ev, pdsa1)
# blupev = bytes(lupev[0])
# print(blupev, len(blupev)) # Let's say it's just single chunk in there

# resolved_lup = LUP.from_bytes(blupev)
# print(resolved_lup.data)
# resolved_event = SecurePacket.from_bytes(
#     base64.b64decode(resolved_lup.data['data']),
#     c2private,
#     base64.b64decode(resolved_lup.data['purpose_info']),
# )
# print(resolved_event.data)



# shared = key=os.urandom(32)
# pdna = PacketDNA(b'lolkek')

# user = User('Server', "Server", "Server", "server", "", "l.n.e.t", '00000000000000000000000000000000')
# ev = MsgCreated(
#     shared,
#     sender=user,
#     recipient=[user],
#     message='Hola espanola'
# )
# # print(ev.data)
# # print(ev.sender.json)
# # print(ev.recipient[0].json)
# # print(bytes(ev))

# # SecurePacket.from_bytes(os.urandom(32), os.urandom(1228))

# chunks = LUP.generate_chunks(ev, pdna)
# print(chunks)
# for chunk in chunks:
#     print(chunk.length)
# decoded = b''.join([base64.b64decode(c.data['data']) for c in chunks])
# print(SecurePacket.from_bytes(shared, decoded).data)