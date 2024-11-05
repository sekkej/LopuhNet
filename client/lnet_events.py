from shared.packets import Event
from shared.shared_utils import PacketDSA
from shared.basic_types import User
from lnet_types import *
from shared.eventflags import EventFlags

class FriendAccepted(Event):
    pId   = 0x101
    pName = 'FriendAccepted'
    flags = 0 + EventFlags.DISPOSABLE

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: User = None,
            data: None = None # Used while decoding
            ):
        super().__init__(
            sender_packet_dsa,
            recipient_public_key,
            sender,
            recipient,
            {
                'pId':   self.pId,
                'pName': self.pName
            }
        )

class Typing(Event):
    pId   = 0x102
    pName = 'Typing'
    flags = 0 + EventFlags.DISPOSABLE

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: User = None,
            data: None = None # Used while decoding
            ):
        super().__init__(
            sender_packet_dsa,
            recipient_public_key,
            sender,
            recipient,
            {
                'pId':   self.pId,
                'pName': self.pName
            }
        )

class GroupCreated(Event):
    pId   = 0x103
    pName = 'GroupCreated'
    flags = 0

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: User = None,
            group: Group = None,
            data: None = None # Used while decoding
            ):
        self.group = group
        super().__init__(
            sender_packet_dsa,
            recipient_public_key,
            sender,
            recipient,
            {
                'pId':   self.pId,
                'pName': self.pName,
                'group': self.group
            }
        )

class MsgCreated(Event):
    pId   = 0x104
    pName = 'MsgCreated'
    flags = 0

    def __init__(self,
            sender_packet_dsa: PacketDSA,
            recipient_public_key: bytes,
            sender: User = None,
            recipient: User = None,
            message: Message = None,
            data: None = None # Used while decoding
            ):
        self.message = message
        super().__init__(
            sender_packet_dsa,
            recipient_public_key,
            sender,
            recipient,
            {
                'pId':   self.pId,
                'pName': self.pName,
                'message': self.message
            }
        )