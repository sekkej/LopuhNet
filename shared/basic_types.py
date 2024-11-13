from __future__ import annotations

import time
import json
from uuid import uuid5, UUID

class JSI:
    """
    Json Serializable Interface
    """
    @property
    def json(self) -> str:
        return json.dumps(self, default=lambda o: o.__dict__)

    @classmethod
    def from_string(cls, data: str):
        instance = cls(*json.loads(data).values())
        return instance

class User(JSI):
    def __init__(self,
                name: str,
                username: str,
                avatar_seed: int,
                # password_hash: str,
                # attached_ip: str, Why do we need it?
                public_key: str,
                public_signkey: str,
                userid: str = None
            ):
        self.name = name
        """Display name"""
        self.username = username
        """Username"""

        self.avatar_seed = avatar_seed
        """
        Avatar seed
        Needed to generate the avatar. Calculates on client-side from hash of a seed-string.
        """

        # self.password_hash = password_hash
        # """Hashed password"""

        # self.attached_ip = attached_ip
        # """Hash of attached IP"""

        self.public_key = public_key
        """Public key used for ciphering CHAKEMDSA"""

        self.public_signkey = public_signkey
        """Public key used for signing CHAKEMDSA"""
        # """Public key for verifying signature of PacketDNA"""

        self.userid = uuid5(
            namespace=UUID(bytes=str(time.time_ns())[:16].encode()),
            name=username
        ).hex if userid is None else UUID(userid).hex
        """User ID (UUID5)"""
    
    def __eq__(self, other_user: User):
        # Key data that if aren't equal to, then return false
        return self.username == other_user.username \
            and self.userid == other_user.userid \
            and self.public_key == other_user.public_key \
            and self.public_signkey == other_user.public_signkey \
    
    @classmethod
    def from_db(cls, data: tuple):
        # Shitcode is unavoidable,
        # Shitcode is everywhere
        if isinstance(data, str):
            return cls.from_string(data)
        elif isinstance(data, User):
            return data
        elif isinstance(data, dict):
            return cls(**data)
        instance = cls(*data[1:])
        return instance

class ServerAccount(User):
    def __init__(self):
        super().__init__('Server', "Server", 0, "", "", '00000000000000000000000000000000')

class Packet:
    def __init__(self, sender: User, recipient: User, data: dict):
        self.sender = sender
        """Sender"""
        self.recipient = recipient
        """Recipient(-s)"""
        self.data = data
        """JSON Data that needs to be transported"""

    @property
    def _json(self) -> str:
        """Used only for debugging and testing"""
        return json.dumps(self, default=lambda o: o.__dict__ if hasattr(o, '__dict__') else str(o))

    @classmethod
    def _from_json(cls, data: str):
        """Used only for debugging and testing"""
        instance = cls(*json.loads(data).values())
        return instance

    def __bytes__(self):
        # LNet Packet Format Standard
        # Encoding

        return f"""
\u001C{User.from_db(self.sender).json}\u001F{User.from_db(self.recipient).json}\u001D{json.dumps(self.data, default=lambda o: o.__dict__ if hasattr(o, '__dict__') else (o.json if hasattr(o, 'json') else str(o)))}\u001C
                """.encode()

    @classmethod
    def from_bytes(cls, data: bytes, **additional_kwargs):
        # LNet Packet Format Standard
        # Decoding

        utf = data.decode('utf-8')
        stripped = utf.strip().strip('\u001C')
        clientsdiv, datadiv = stripped.split('\u001D')
        contactinfo = clientsdiv.split('\u001F')
        data = json.loads(datadiv)
        sender = User.from_string(contactinfo[0])
        recipient = User.from_string(contactinfo[1])

        # Python.
        clazz = cls(**{'sender': sender, 'recipient': recipient, 'data': data}, **additional_kwargs)
        clazz.data = data
        return clazz