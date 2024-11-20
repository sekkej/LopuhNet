import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

import lnet_events as events
import lnet_types as types

import asyncio
import socket
import base64
from asyncio_events import Events
from base_logger import logging, base_logger
from shared.dbmanager import Database
from shared.basic_types import User, ServerAccount
from shared.packets import *

global _events
_eventlist = (
    # Low-level transport events
    *(
        'on_netmessage', 'on_event'
    ),

    # Specifically API Client events
    *(
        'on_start', 'on_ready'
    ),

    # Friend requests events
    *(
        'on_friend_request', 'on_friend_request_accepted'
    ),

    # Messages managing events
    *(
        'on_message', 'on_message_edit', 'on_message_delete',
    ),
)

class LNetAPI:
    def __init__(
            self,
            server_host: str,
            server_port: int,
            database_path: str = 'lnet.db',
            logger: logging.Logger = base_logger,
            account_data: dict = None
        ):
        self.server_host = server_host
        self.server_port = server_port

        self.events = Events(_eventlist)
        self.logger = logger

        self._database = Database(logger, database_path)

        self._public_key = None
        self._private_key = None
        self._pdsa = None
        self._server_public = None

        self._friends = None
        self._groups = None

        if account_data:
            self.user = User.from_string(account_data['user'])
            self.authorized = False

            self._pdsa = PacketDSA(base64.b64decode(account_data['signpublic']), base64.b64decode(account_data['signprivate']))
            self._private_key = base64.b64decode(account_data['private'])
            self._public_key = base64.b64decode(account_data['public'])
            self._friends = account_data['friends']
            self._groups = account_data['groups']
        else:
            self._pdsa = PacketDSA()
            self._public_key, self._private_key = CHAKEM.generate_keys()
        
        self._running = False
        self._sock = None

        self._transmission_results = {}
        self._frequests = {}
        self._statuses = {}

    def event(self, func):
        self.events.handler(func)

    async def send(self, data: bytes, _socket: socket.socket = None):
        sock = self._sock if _socket is None else _socket
        sock.sendall(len(data).to_bytes(4, 'big'))
        sock.sendall(data)
    
    async def _receive(self, size, _socket: socket.socket = None):
        data = bytearray()
        while len(data) < size:
            packet = _socket.recv(5*1024*1024)
            if not packet:  # Connection closed
                raise ConnectionError("Connection closed before receiving all data")
            data.extend(packet)
        return bytes(data)
    
    async def receive(self, _socket: socket.socket = None):
        sock = self._sock if _socket is None else _socket
        try:
            data_length = int.from_bytes(sock.recv(4), 'big')
            return await self._receive(data_length, sock)
        except:
            return None

    def _get_avatar_seed(seed: str) -> int:
        return xxhash.xxh128(seed).intdigest() % (10 ** 10)

    async def authorize(self):
        self.logger.info(f"Requesting authentication...")

        if self.authorized:
            raise RuntimeError("Already authorized!")

        if self.user is None:
            raise RuntimeError("No account found to authenticate!")
        
        await self.send(
            bytes(Authentication(
                self._pdsa,
                self._server_public,
                sender=self.user,
                recipient=ServerAccount(),
                user=self.user
            ))
        )

        try:
            authentication_result = SecurePacket.from_bytes(
                (await self.receive()),
                self._private_key,
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
        self.authorized = True
        self.logger.info("Ready to use!")

        return True, 'Ready to use!'

    async def register(self, name: str, username: str, avatar_seed: str):
        self.logger.info("Registrating user...")

        if self.authorized:
            raise RuntimeError("Already authorized!")
        
        public_key_enc = base64.b64encode(self.public_key).decode()
        public_signkey_enc = base64.b64encode(self.pdsa.public).decode()
        user = User(name, username, self._get_avatar_seed(avatar_seed), public_key_enc, public_signkey_enc)

        self.logger.debug("Sending Registration packet...")
        await self.send(
            bytes(Registration(
                self._pdsa,
                self._server_public,
                sender=user,
                recipient=ServerAccount(),
                user=user
            ))
        )

        try:
            registration_result = SecurePacket.from_bytes(
                (await self.receive()),
                self._private_key,
                b'Registration',
                _verify_signature=False
            ).data
        except:
            self.logger.error('RegistrationResult packet decryption error, might be a packet mismatch.')
            return False, 'Expected RegistrationResult packet from server, got unknown one.'

        if registration_result['message'] == 'Success!':
            self.logger.info("Successfully registered! Saving all the data...")

            self._database.register(user)

            self.user = user
            self.authorized = True
            self._friends = {}
            self._groups = {}
            
            self.logger.info("Ready to use!")
            return True, 'Ready to use!'
        
        self.logger.error(f"Considering server's response it's registration failure: {registration_result['message']}")
        return False, registration_result['message']

    async def connect(self):
        self.logger.info(f"Connecting to {self.server_host}:{self.server_port}")
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.server_host, self.server_port))
        self.logger.info("Connected to server")

    async def _fetch_server_key(self):
        self.logger.info(f"Requesting server's individual encryption key...")
        await self.send(b'KEYEXCHANGE')
        self._server_public = (await self.receive())[7:]
        self.logger.info("Saved server's personal one-time individual encryption key!")

    async def _run(self):
        await self.connect()
        self._running = True
        await self._fetch_server_key()
        self.events.on_start()

        asyncio.get_running_loop().create_task(self._listen_netmessages())
        # while True:
        #     await asyncio.sleep(1)
    
    async def send_event(self, event: events.Event):
        self.logger.debug(f'Sending an event (eid: {event.eid})...')
        self._transmission_results[event.eid] = None
        bevent = bytes(event)
        await self.send(b'TRANSMISSION:' + event.eid.encode() + b':' + event.recipient.userid.encode() + b':' + bevent)

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
            return True, 'Success!'
        
        self.logger.error(f'Transmission failure: no online peer with given User ID found.')
        self._transmission_results.pop(event.eid)
        return False, 'No online peer with given User ID found.'

    async def send_friend_request(self, username: str):
        self.logger.debug(f'Sending a friend request to {username}...')
        self._frequests[username] = None
        await self.send(f'FREQUEST:{username}'.encode())

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
            return True, 'Success!'
        
        self.logger.error(f'Friend request failure: no online peer with given username found.')
        self._frequests.pop(username)
        return False, 'No online peer with given username found.'

    async def _listen_netmessages(self):
        while not self.authorized:
            await asyncio.sleep(.1)
        
        self.events.on_ready()
        self.logger.debug(f'Running message listener...')

        while self._running:
            try:
                data = await self.receive()
                self.logger.debug(f"{data}")
                if not data:
                    if not self._running:
                        break
                    continue
                self.events.on_netmessage(data)
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Error in listening loop: {e}")
                break
    
    # @_events.handler
    # async def on_netmessage(self, data):
    #     self.logger.debug('Recv:', len(data))

    async def close(self):
        self._running = False
        self._sock.close()
        self.logger.info("Connection closed")

    def start(self):
        asyncio.run(self._run())
    
    def _force_stop(self):
        self._running = False
        self._sock.close()