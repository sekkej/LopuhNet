# server
import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

import logging
from colorlog import ColoredFormatter

log_format = (
    '%(asctime)s '
    '%(log_color)s'
    '%(levelname)-8s'
    '%(reset)s '
    '%(message)s'
)

formatter = ColoredFormatter(
    log_format,
    datefmt='%Y-%m-%d %H:%M:%S',
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    }
)

handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

# server.py
import socket
from shared.dbmanager import Database, DatabaseException
from shared.basic_types import User, ServerAccount
from shared.packets import *
from shared.shared_utils import SocketUtils #, ECDH, AESCipher,
from events import Events
import threading
import traceback

class ServerEvents(Events):
    __events__ = ('on_netmessage', )

class Server:
    def __init__(self, logger: logging.Logger):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        """Socket"""
        
        self.logger = logger
        """Logger"""

        self.db = Database(logger)
        """Database"""

        self.clients = {}
        """Known connected clients"""
        self.clients : dict['socket._RetAddress', tuple[socket.socket, User]]

        self._auth = {}
        """Clients saved authentications"""

        self.events = ServerEvents()
        """Events"""

        self.save_events = False
        """
        If this option is enabled, then server will save all sent events.
        Note: all online peers still will save all events, although server does it.
        Note: enabling this, leads to less private but more convenient communication
        """

        self.cached_events = [{}]
        """Buffer of cached events data. Used when client requests a retrial of receiving event."""

        self.maximum_cached_events_length = 256
        """Maximum size of Server.cached_events. Defaults to 256"""

        self._init_events()

    def start(self):
        self.s.bind(('0.0.0.0', 9229))
        sname = self.s.getsockname()
        self.logger.info(f"Running server instance on {sname[0]}:{sname[1]}")
        self.s.listen()

        while True:
            sock, addr = self.s.accept()
            self.logger.info(f"Client {addr} connected!")
            threading.Thread(target=self.listen_client, args=(sock, addr)).start()
    
    def unsafe(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Notice that it is really unwanted to use the variable logger like this
                # So, it is the only place where it's being used like this
                logger.error(f"An error occurred in {func.__name__}: {traceback.format_exc()}")
                return None
        return wrapper
    
    def _receive(self, sock, size):
        data = bytearray()
        while len(data) < size:
            packet = sock.recv(5*1024*1024)
            if not packet:  # Connection closed
                raise ConnectionError("Connection closed before receiving all data")
            data.extend(packet)
        return bytes(data)

    def send(self, sock: socket.socket, data: bytes):
        sock.sendall(len(data).to_bytes(4, 'big'))
        sock.sendall(data)

    @unsafe
    def listen_client(self, sock: socket.socket, addr):
        sock.settimeout(5)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 5*1024*1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 5*1024*1024)
        while True:
            try:
                data_length = int.from_bytes(sock.recv(4), 'big')
                data = self._receive(sock, data_length)
                if not data:
                    self.logger.info(f"Client {addr} disconnected...")
                    if addr in self._auth:
                        self._auth.pop(addr)
                    if addr in self.clients:
                        self.clients.pop(addr)
                    break
                self.events.on_netmessage(sock, data, addr)
            except socket.timeout:
                continue
            except ConnectionError as e:
                self.logger.error(f"Connection error with {addr}: {e}")
                if addr in self._auth:
                    self._auth.pop(addr)
                if addr in self.clients:
                    self.clients.pop(addr)
                break
    
    @unsafe
    def on_authentication(self, sock: socket.socket, data: bytes, addr: tuple):
        authentication_packet = SecurePacket.from_bytes(data, self._auth[addr][1], b'Authentication')
        authentication_data = authentication_packet.data
        
        self.logger.info('Received Authentication packet, proceeding...')

        if User.from_string(json.dumps(authentication_data['user'], ensure_ascii=False)) != authentication_packet.sender:
            self.logger.error('Peer tried to authenticate as a different user.')
            self.send(sock,
                bytes(AuthenticationResult(
                    base64.b64decode(authentication_packet.sender.public_key),
                    sender=ServerAccount(),
                    recipient=authentication_packet.sender,
                    message='Peer tried to authenticate as a different user.'
                ))
            )
            return
        
        self.clients[addr] = (sock, authentication_packet.sender)
        self.send(sock,
                bytes(AuthenticationResult(
                    base64.b64decode(authentication_packet.sender.public_key),
                    sender=ServerAccount(),
                    recipient=authentication_packet.sender,
                    message='Success!'
                ))
            )
        self.logger.info('Successfully authenticated peer.')

    @unsafe
    def on_registration(self, sock: socket.socket, data: bytes, addr: tuple):
        if addr not in self._auth and addr not in self.clients:
            return
        
        if addr in self._auth and len(self._auth[addr]) >= 2:
            try:
                registration_packet = SecurePacket.from_bytes(data, self._auth[addr][1], b'Registration')
                registration_data = registration_packet.data
            except:
                self.on_authentication(sock, data, addr)
                return
            
            self.logger.info('Received Registration packet, proceeding...')
            client_user = User(**registration_data['user'])

            try:
                registration_result = self.db.register(client_user)
                registered = isinstance(registration_result, bool)
                self.send(sock,
                    bytes(RegistrationResult(
                        base64.b64decode(registration_data['user']['public_key']),
                        sender=ServerAccount(),
                        recipient=client_user,
                        message= 'Success!' if registered else str(registration_result[1])
                    ))
                )

                if registered:
                    self.clients[addr] = (sock, client_user)
                    self.logger.info('Successfully registered and authenticated peer!')
            except Exception as e:
                self.logger.info(f'Couldnt authenticate peer: {traceback.format_exc()}')
                self.send(sock,
                    bytes(RegistrationResult(
                        base64.b64decode(registration_data['user']['public_key']),
                        sender=ServerAccount(),
                        recipient=client_user,
                        message='Internal error.'
                    ))
                )
    
    @unsafe
    def on_keyexchange(self, sock: socket.socket, data: bytes, addr: tuple):
        if data == b'KEYEXCHANGE':
            self.logger.info('Peer connected, generating exclusive one-session keys...')

            if addr in self._auth:
                self._auth.pop(addr)
            if addr in self.clients:
                self.clients.pop(addr)
            
            exclusive_keys = CHAKEM.generate_keys()
            self._auth[addr] = (*exclusive_keys,)
            self.send(sock, b'PUBLIC:' + exclusive_keys[0])
            
            self.logger.info('Public key sent!')
        else:
            self.on_registration(sock, data, addr)
    
    @unsafe
    def on_friend_request(self, sock: socket.socket, data: bytes, addr: tuple):
        if data.startswith(b'FREQUEST:'):
            if addr not in self.clients:
                return
            
            self.logger.debug('Peer sent friend request, proceeding...')
            readable_data = data.decode().split(':')

            frequest_sender = self.clients[addr][1]
            frequest_peername = readable_data[1]

            for client in self.clients.values():
                if client[1].username == frequest_peername:
                    self.send(client[0], bytes(FriendRequest(
                        base64.b64decode(client[1].public_key),
                        sender=frequest_sender,
                        recipient=client[1],
                    )))
                    self.send(sock, f'FREQUEST:{frequest_peername}:1'.encode())
                    self.logger.debug(f'Transmission of FriendRequest (to: {frequest_peername}) succeed.')
                    return
            
            self.logger.error(f'Transmission of FriendRequest (to: {frequest_peername}) failed, recipient is not found or online either.')
            self.send(sock, f'FREQUEST:{frequest_peername}:0'.encode())
        else:
            self.on_keyexchange(sock, data, addr)

    @unsafe
    def on_invalid_event_retrial(self, sock: socket.socket, data: bytes, addr: tuple):
        if data.startswith(b'INVALID/RETRY:'):
            if addr not in self.clients:
                return
            
            self.logger.debug('Peer requested transmission retrial, proceeding...')
            readable_data = data.decode().split(':')
            event_id = readable_data[1]
            
            for cevent in self.cached_events:
                if event_id in cevent:
                    self.send(sock, f'EVENT:{event_id}:'.encode() + cevent[event_id])
                    return
            
            self.send(sock, f'EVENT:{event_id}:NONE'.encode())
        else:
            self.on_friend_request(sock, data, addr)

    @unsafe
    def on_transmission(self, sock: socket.socket, data: bytes, addr: tuple):
        if data.startswith(b'TRANSMISSION:'):
            if addr not in self.clients:
                return

            self.logger.debug('Peer requested transmission, proceeding...')
            readable_data = data[13:]
            event_id = readable_data[:readable_data.index(b':')].decode()

            readable_data = readable_data[len(event_id)+1:]
            requested_peer = readable_data[:readable_data.index(b':')].decode()

            data_to_transmit = readable_data[len(requested_peer)+1:]

            for client in self.clients.values():
                if client[1].userid == requested_peer:
                    if len(self.cached_events) >= self.maximum_cached_events_length:
                        desired_sub = len(self.cached_events)-self.maximum_cached_events_length
                        self.cached_events = self.cached_events[desired_sub:]
                    self.cached_events.append({event_id: data_to_transmit})
                    
                    self.send(client[0], f'EVENT:{event_id}:'.encode() + data_to_transmit)
                    self.send(sock, f'TRANSMISSION:{event_id}:1'.encode())

                    self.logger.debug(f'Transmission of event (eid: {event_id}) to user: {client[1].userid} succeed.')
                    return
            
            self.logger.error(f'Transmission of event (eid: {event_id}) failed, recipient is not online or not found.')
            self.send(sock, f'TRANSMISSION:{event_id}:0'.encode())
        else:
            self.on_invalid_event_retrial(sock, data, addr)
    
    @unsafe
    def on_peer_statuscheck(self, sock: socket.socket, data: bytes, addr: tuple):
        if data.startswith(b'CHECKSTATUS:'):
            if addr not in self.clients:
                return

            self.logger.debug('Peer requested another peer status check, proceeding...')
            readable_data = data.decode().split(':')
            
            for client in self.clients.values():
                if client[1].userid == readable_data[1]:
                    self.send(sock, f'CHECKSTATUS:{readable_data[1]}:1'.encode())
                    return
            
            self.send(sock, f'CHECKSTATUS:{readable_data[1]}:0'.encode())
        else:
            self.on_transmission(sock, data, addr)

    def on_netmessage(self, sock: socket.socket, data: bytes, addr: tuple):
        if data == b'?':
            self.logger.debug('Peer pinged server, sending pong...')
            self.send(sock, b'!')
        else:
            self.on_peer_statuscheck(sock, data, addr)

    def _init_events(self):
        self.events.on_netmessage += self.on_netmessage

if __name__ == "__main__":
    # try:
        s = Server(logger)
        # import time
        # time.sleep(5)
        # s.ftest()
        s.maximum_cached_events_length = 256
        s.start()
    # except Exception as e:
    #     input(e.with_traceback(None))