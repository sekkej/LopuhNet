import time
import xxhash
from uuid import uuid5, UUID
from shared.basic_types import User, JSI

class Picture(JSI):
    def __init__(self,
                filename: str,
                b64data: str
            ):
        
        self.filename = filename
        self.b64data = b64data

class Message(JSI):
    def __init__(self,
                author: User,
                channel: str,
                content: str,
                timestamp: int,
                pictures: list[Picture] = [],
                reply_to: 'Message' = None,
                msgid: str = None
            ):
        
        self.author = author
        self.channel = channel
        self.content = content
        self.timestamp = timestamp
        self.pictures = pictures
        self.reply_to = reply_to
        self.msgid = uuid5(
            namespace=UUID(bytes=str(time.time_ns())[:16].encode()),
            name=xxhash.xxh128(f"{author}{channel}{content}{timestamp}").hexdigest()
        ).hex if msgid is None else UUID(msgid).hex

class Group(JSI):
    def __init__(self,
                name: str,
                members: list[User],
                created_at: int,
                groupid: str = None
            ):
        self.name = name
        self.members = members
        self.created_at = created_at
        self.groupid = uuid5(
            namespace=UUID(bytes=str(time.time_ns())[:16].encode()),
            name=xxhash.xxh128(f"{name}{created_at}").hexdigest()
        ).hex if groupid is None else UUID(groupid).hex