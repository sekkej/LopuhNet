# client
import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

import logging
# from colorlog import ColoredFormatter

# log_format = (
#     '%(asctime)s '
#     '%(log_color)s'
#     '%(levelname)-8s'
#     '%(reset)s '
#     '%(message)s'
# )

# formatter = ColoredFormatter(
#     log_format,
#     datefmt='%Y-%m-%d %H:%M:%S',
#     reset=True,
#     log_colors={
#         'DEBUG': 'cyan',
#         'INFO': 'green',
#         'WARNING': 'yellow',
#         'ERROR': 'red',
#         'CRITICAL': 'red,bg_white',
#     }
# )

# handler = logging.StreamHandler()
# handler.setFormatter(formatter)

# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# logger.addHandler(handler)

# client.py
import time
import threading
import socket
import bcrypt
import base64
from shared.dbmanager import Database
from shared.basic_types import User, ServerAccount
from shared.packets import *
from lnet_events import *
from util import get_avatar_seed
from events import Events
import traceback

class ClientEvents(Events):
    __events__ = ('on_netmessage', 'on_event')

class Client:
    __logger = None

    def __init__(self,
                 logger: logging.Logger,
                 predecessor_lnet_event_fire,
                 trusted_consts: dict,
                 cached_data: dict = None,
                 database_name: str = 'lnet'
        ):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        """Socket"""
        self.s.settimeout(5)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 5*1024*1024)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 5*1024*1024) 

        self.logger = logger
        """Logger"""
        self.__logger = logger
        
        self.db = Database(logger, database_name)
        """Database"""

        self.events = ClientEvents()
        """Events"""

        self._sip = trusted_consts["server_ip"]
        """Server's IP for connection from trusted consts"""
        self._sport = trusted_consts["server_port"]
        """Server's port for connection from trusted consts"""
        self._saddr = (self._sip, self._sport)
        """Server's full socket address"""
        self._spublic = None
        """Server's exclusive one-session usable public key"""
        
        self.account = None
        """Self User instance"""
        self.pdsa = None
        """PacketDSA instance"""
        self.private_key = None
        """Extremely-really-very-extra-hugely secret private key, like a Discord token. NEVER leak this, otherwise FBI will come soon"""
        self.public_key = None
        """Not extremely-really-very-extra-hugely secret private key, but public one!"""

        self.cached_data = None
        self._cached_data_path = cached_data
        self._cached_data_busy = False

        self.friends = None
        """Friends dictionary: {userid: User}"""

        self.groups = None
        """Groups dictionary: {groupid: Group}"""

        if os.path.exists(cached_data):
            self.cached_data = json.load(open(self._cached_data_path, 'r', encoding='utf-8'))
            self.account = (False, User.from_string(self.cached_data['user']))
            self.pdsa = PacketDSA(base64.b64decode(self.cached_data['signpublic']), base64.b64decode(self.cached_data['signprivate']))
            self.private_key = base64.b64decode(self.cached_data['private'])
            self.public_key = base64.b64decode(self.cached_data['public'])
            self.friends = self.load_friends()
            self.groups = self.load_groups()
        else:
            self.pdsa = PacketDSA()
            self.public_key, self.private_key = CHAKEM.generate_keys()
        
        self.allow_serverside_saving = False
        """
        If Server is able of saving your events AND this option is enabled, then server will save all your messages.
        Note: all online peers still will save all your messages, although server does it.
        Note: enabling this, leads to less private but more convenient communication
        """

        self._transmission_results = {}
        self._frequests = {}
        self._statuses = {}
        # self._allow_thread_blocking = _allow_thread_blocking

        self._last_time_server_pong = 0
        self._listener_thread = None
        self._listening = False

        self._lnet_fire_event = predecessor_lnet_event_fire

        self._init_events()
    
    def load_friends(self) -> dict:
        if 'friends' in self.cached_data:
            return self.cached_data['friends']
        return {}
    
    def add_friend(self, user: User):
        if self._cached_data_busy:
            raise RuntimeError("Cached data file is busy!")
        
        self._cached_data_busy = True
        self.friends[user.userid] = user.__dict__
        self.cached_data['friends'] = self.friends
        json.dump(self.cached_data, open(self._cached_data_path, 'w', encoding='utf-8'), ensure_ascii=False)
        self._cached_data_busy = False
    
    def remove_friend(self, user: User):
        if self._cached_data_busy:
            raise RuntimeError("Cached data file is busy!")
        
        self._cached_data_busy = True
        if user.userid in self.friends:
            self.friends.pop(user.userid)
        self.cached_data['friends'] = self.friends
        json.dump(self.cached_data, open(self._cached_data_path, 'w', encoding='utf-8'), ensure_ascii=False)
        self._cached_data_busy = False

    def load_groups(self) -> dict:
        if 'groups' in self.cached_data:
            return self.cached_data['groups']
        return {}
    
    def add_group(self, group: Group):
        if self._cached_data_busy:
            raise RuntimeError("Cached data file is busy!")
        
        self._cached_data_busy = True
        group_dict = group.__dict__
        group_dict['members'] = [m.__dict__ for m in group_dict['members']]
        self.groups[group.groupid] = group_dict
        self.cached_data['groups'] = self.groups
        json.dump(self.cached_data, open(self._cached_data_path, 'w', encoding='utf-8'), ensure_ascii=False)
        self._cached_data_busy = False
    
    def remove_group(self, group: Group):
        if self._cached_data_busy:
            raise RuntimeError("Cached data file is busy!")
        
        self._cached_data_busy = True
        if group.groupid in self.groups:
            self.groups.pop(group.groupid)
        self.cached_data['groups'] = self.groups
        json.dump(self.cached_data, open(self._cached_data_path, 'w', encoding='utf-8'), ensure_ascii=False)
        self._cached_data_busy = False

    def send(self, data: bytes, _socket: socket.socket = None):
        sock = self.s if _socket is None else _socket
        sock.sendall(len(data).to_bytes(4, 'big'))
        sock.sendall(data)
    
    def _receive(self, size, _socket: socket.socket = None):
        data = bytearray()
        while len(data) < size:
            packet = _socket.recv(5*1024*1024)
            if not packet:  # Connection closed
                raise ConnectionError("Connection closed before receiving all data")
            data.extend(packet)
        return bytes(data)
    
    def receive(self, _socket: socket.socket = None):
        sock = self.s if _socket is None else _socket
        try:
            data_length = int.from_bytes(sock.recv(4), 'big')
            return self._receive(data_length, sock)
        except:
            return None

    def is_server_alive(self, initial=False):
        self.logger.debug(f"Checking if server is alive...")
        try:
            if initial:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 5*1024*1024)
                connected = s.connect_ex(self._saddr)

                if connected != 0:
                    return False
                
                self.send(b'?', s)
                reply = self.receive(s)
                s.close()

                return reply == b'!'
            else:
                timeout = time.time() + 8
                while time.time() - self._last_time_server_pong > 8:
                    if time.time() > timeout:
                        self.logger.error(f'Ping response time out.')
                        return False
                    time.sleep(.1)
                return True
        except socket.error:
            return False

    def listen_messages(self):
        self.logger.info("Listening net-messages...")
        self._listening = True
        while self._listening:
            try:
                data = self.receive()
                if not data:
                    if not self._listening:
                        break
                    continue

                    # if not self.is_server_alive(initial=False):
                    #     self.db.cur.close()
                    #     self.logger.warning(f"Server closed connection...")
                    #     break

                self.events.on_netmessage(data)
            except socket.timeout:
                continue
            except ConnectionError as e:
                self.db.cur.close()
                self.logger.error(f"Connection error with server: {e}")
                break

    def start(self):
        self.logger.info("Starting client...")

        if not self.is_server_alive(initial=True):
            raise ConnectionError("Server is not alive. Cannot start Client.")

        # Connect to server and request onetime-keys exchange
        self.s.connect(self._saddr)
        self.logger.info("Requesting key-exchange...")
        self.send(b'KEYEXCHANGE')
        self._spublic = self.receive()[7:]
        self.logger.info("Successfully started client!")
        self.logger.debug("Waiting for further command: to register or to authenticate...")
    
    def register(self, name: str, username: str, avatar_seed: str):
        self.logger.info("Registrating user...")

        if not self.is_server_alive(initial=True):
            return False, RuntimeError("Server is not alive, cannot proceed registration request.")
        
        public_key_enc = base64.b64encode(self.public_key).decode()
        public_signkey_enc = base64.b64encode(self.pdsa.public).decode()
        user = User(name, username, get_avatar_seed(avatar_seed), public_key_enc, public_signkey_enc)

        self.logger.debug("Sending Registration packet...")
        self.send(
            bytes(Registration(
                self.pdsa,
                self._spublic,
                sender=user,
                recipient=ServerAccount(),
                user=user
            ))
        )

        try:
            registration_result = SecurePacket.from_bytes(
                self.receive(),
                self.private_key,
                b'Registration',
                _verify_signature=False
            ).data
        except:
            self.logger.error('RegistrationResult packet decryption error, might be a packet mismatch.')
            return False, 'Expected RegistrationResult packet from server, got unknown one.'

        if registration_result['message'] == 'Success!':
            self.logger.info("Successfully registered! Saving all the data...")

            self.db.register(user)

            self.cached_data = {
                    'public': public_key_enc,
                    'private': base64.b64encode(self.private_key).decode(),
                    'signpublic': public_signkey_enc,
                    'signprivate': base64.b64encode(self.pdsa.private).decode(),
                    'user': user.json,
                    'friends': {},
                    'groups': {}
                }
            json.dump(
                self.cached_data,
                open(self._cached_data_path, 'w', encoding='utf-8'),
                ensure_ascii=False
            )
            
            self.account = user
            
            self.logger.info("Ready to use!")

            return True
        
        self.logger.error(f"Considering server's response it's registration failure: {registration_result['message']}")
        self._listener_thread = threading.Thread(target=self.listen_messages)
        self._listener_thread.start()
        
        return False, registration_result['message']
    
    def authenticate(self):
        self.logger.info(f"Requesting authentication...")

        if self.account is None:
            raise RuntimeError("No account found to authenticate!")
        
        self.send(
            bytes(Authentication(
                self.pdsa,
                self._spublic,
                sender=self.account[1],
                recipient=ServerAccount(),
                user=self.account[1]
            ))
        )

        try:
            authentication_result = SecurePacket.from_bytes(
                self.receive(),
                self.private_key,
                b'Authentication',
                _verify_signature=False
            ).data
        except:
            self.logger.error('AuthenticationResult packet decryption error, might be a packet mismatch.')
            return False, 'Expected AuthenticationResult packet from server, got unknown one.'
        
        if authentication_result['message'] != 'Success!':
            self.logger.error(f"Considering server's response it's authentication failure: {authentication_result['message']}")
            return False, authentication_result['message']
        
        self.logger.info("Successfully authenticated!")
        self.account = self.account[1]
        self._listener_thread = threading.Thread(target=self.listen_messages)
        self._listener_thread.start()
        self.logger.info("Ready to use!")

        return True

    def send_event(self, event: Event):
        self.logger.debug(f'Sending an event (eid: {event.eid})...')
        self._transmission_results[event.eid] = None
        bevent = bytes(event)
        self.send(b'TRANSMISSION:' + event.eid.encode() + b':' + event.recipient.userid.encode() + b':' + bevent)

        self.logger.debug(f'Waiting answer from server...')
        timeout = time.time() + 5
        while self._transmission_results[event.eid] is None:
            if time.time() > timeout:
                self.logger.error(f'Transmission response time out.')
                self._transmission_results.pop(event.eid)
                return False, 'Time out.'
            time.sleep(.1)
        
        if self._transmission_results[event.eid] == True:
            if EventFlags.DISPOSABLE.name not in EventFlags.get_flags(event.flags):
                self.db.add_event(time.time_ns(), event.recipient.userid, bevent, event.eid)
            self.logger.debug(f'Transmission succeed.')
            self._transmission_results.pop(event.eid)
            return True
        
        self.logger.error(f'Transmission failure: no online peer with given User ID found.')
        self._transmission_results.pop(event.eid)
        return False, 'No online peer with given User ID found.'
    
    def send_friend_request(self, username: str):
        self.logger.debug(f'Sending a friend request to {username}...')
        self._frequests[username] = None
        self.send(f'FREQUEST:{username}'.encode())

        self.logger.debug(f'Waiting answer from server...')
        timeout = time.time() + 5
        while self._frequests[username] is None:
            if time.time() > timeout:
                self.logger.error(f'Friend request response time out.')
                self._frequests.pop(username)
                return False, 'Time out.'
            time.sleep(.1)
        
        if self._frequests[username] == True:
            self.logger.debug(f'Friend request sent.')
            self._frequests.pop(username)
            return True
        
        self.logger.error(f'Friend request failure: no online peer with given username found.')
        self._frequests.pop(username)
        return False, 'No online peer with given username found.'
    
    def check_peer_status(self, userid: str):
        self.logger.debug(f"Checking peer's (uid: {userid}) status...")
        self._statuses[userid] = None
        self.send(f'CHECKSTATUS:{userid}'.encode())

        self.logger.debug(f'Waiting answer from server...')
        timeout = time.time() + 5
        while self._statuses[userid] is None:
            if time.time() > timeout:
                self.logger.error(f'Check status response time out.')
                self._statuses.pop(userid)
                return False
            time.sleep(.1)
        
        if self._statuses[userid] == True:
            self.logger.debug(f'Peer status is online.')
            self._statuses.pop(userid)
            return True
        
        self.logger.error(f'Peer status is offline.')
        self._statuses.pop(userid)
        return False
    
    def on_netmessage(self, data: bytes):
        self.logger.debug('Got message from server...')

        if data == b'!':
            self._last_time_server_pong = time.time()
            return
        
        try:
            if data.startswith(b'CHECKSTATUS:'):
                response = data.decode().split(':')
                self._statuses[response[1]] = response[2] == '1'
                return

            if data.startswith(b'TRANSMISSION:'):
                response = data.decode().split(':')
                self._transmission_results[response[1]] = response[2] == '1'
                return
            
            if data.startswith(b'FREQUEST:'):
                response = data.decode().split(':')
                self._frequests[response[1]] = response[2] == '1'
                return

            if data.startswith(b'EVENT:'):
                readable_data = data[6:]
                event_id = readable_data[:readable_data.index(b':')].decode()
                recv_data = readable_data[len(event_id)+1:]

                if recv_data == b'NONE':
                    self.logger.error(f"Failed to decrypt event. Event id: {event_id}")
                    return

                try:
                    self.events.on_event(Event.from_bytes(
                        recv_data,
                        self.private_key
                    ), recv_data)
                except Exception as e:
                    self.logger.error(f"Got invalid event, retrying: {traceback.format_exc()}")
                    self.send(f'INVALID/RETRY:{event_id}'.encode())
        except Exception as e:
            self.logger.error(f"Failed to identify or proceed network message: {traceback.format_exc()}")

    def on_event(self, event: Event, original_data: bytes):
        if event.data['pId'] == FriendRequest.pId:
            self._lnet_fire_event('on_friend_request', event.sender)
        elif event.data['pId'] == FriendAccepted.pId:
            self.add_friend(event.sender)
            self._lnet_fire_event('on_friend_accepted', event.sender)
        
        if event.sender.userid not in self.friends:
            self.logger.warning("Peer tried to raise an event without being in friend list.")
            return

        match event.data['pId']:
            case Typing.pId:
                self._lnet_fire_event('on_typing', event.sender)
            case MsgCreated.pId:
                msg = Message(**event.data['message'])
                msg.author = User(**msg.author)
                if not msg.author == event.sender:
                    self.logger.warning("Peer sent MsgCreated with insufficient permissions.")
                    return
                
                msg.timestamp = time.time_ns()
                msg.content = msg.content[:4000]
                if len(msg.content) == 0 and len(msg.pictures) == 0:
                    self.logger.warning("Peer sent empty Message in MsgCreated.")
                    return
                
                pics = msg.pictures.copy()
                msg.pictures.clear()
                for pic in pics:
                    msg.pictures.append(Picture(**pic))
                
                self.db.add_event(time.time_ns(), event.recipient.userid, original_data, event.eid)
                self._lnet_fire_event('on_message', msg)
            case GroupCreated.pId:
                group = Group(**event.data['group'])
                if len(group.name) < 0 or len(group.name) > 64:
                    self.logger.warning("Peer tried to create Group with invalid name.")
                    return

                members = []
                for member in group.members:
                    members.append(User(**member))
                group.members = members

                if event.sender not in group.members:
                    self.logger.warning("Peer tried to create Group without themselves in it.")
                    return
                
                if len(group.members) < 3 or len(group.members) > 10:
                    self.logger.warning("Peer tried to create Group with invalid number of members.")
                    return

                self.add_group(group)
                self._lnet_fire_event('on_group_created', group)

    def _init_events(self):
        self.events.on_netmessage += self.on_netmessage
        self.events.on_event += self.on_event
    
# if __name__ == "__main__":
#     try:
#         import json
#         # c = Client(logger, json.load(open('trusted_consts.json')), _friends_path='friends_sekkej.json')
#         c = Client(
#             logger,
#             json.load(open('trusted_consts.json')),
#             json.load(open('cached_data_sekkej.json')),
#             'friends_sekkej.json'
#         )
#         c.start()

#         # logger.debug(f"Registration: {c.register('lnet uid1', 'sekkej', 'sekkej')}")
#         # logger.debug(f"Registration: {c.register('Mr. President', 'peterpavel', 'peterpavel')}")
#         # logger.debug(f"Registration: {c.register('James Warren', 'jamezwarren', 'jameswarren')}")

#         logger.debug(f'Authentication: {c.authenticate()}')

#         logger.debug(f"Friend request: {c.send_friend_request('peterpavel')}")

#         # peterpavel = c.db.fetch_user(username='peterpavel')
#         # print('Peter Pavel:', peterpavel)

#         # while True:
#         #     event = MsgCreated(
#         #         c.pdsa,
#         #         base64.b64decode(peterpavel.public_key),
#         #         sender=c.account,
#         #         recipient=[peterpavel],
#         #         message=input('>> ')
#         #     )
#         #     print('Basic event usage:', c.send_event(event))
#         input()
#     except Exception as e:
#         raise e
#         input(e.with_traceback(None))