import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

import asyncio

import json
import base64
import time

from shared.asyncio_events import Events
from shared.base_logger import logging, base_logger
from shared.dbmanager import Database
from shared.basic_types import User, ServerAccount
from shared.packets import *
from shared.shared_utils import ProofOfWorkSession, CaptchaManager

import traceback

from io import BytesIO

class Peer:
    """Peer model"""
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
    
    @property
    def address(self):
        return self._writer.get_extra_info('peername')

    async def send(self, data: bytes):
        """Send data data to peer

        Returns:
            bytes: data
        """

        # Affirm data length
        self._writer.write(len(data).to_bytes(4, 'big'))
        await self._writer.drain()

        # Send the data now
        self._writer.write(data)
        await self._writer.drain()

    async def _receive(self, size):
        data = bytearray()
        estimated_size = size
        while len(data) < size:
            if estimated_size <= 0:
                break

            packet = await self._reader.read(estimated_size)
            if not packet:  # Connection closed
                raise ConnectionError("Connection closed before receiving all data")
            
            data.extend(packet)
            estimated_size -= len(packet)
        return bytes(data)

    async def receive(self):
        """Receive data from peer

        Returns:
            bytes: data
        """
        data_length = await self._reader.read(4) # Read data length
        if len(data_length) != 4:
            raise RuntimeError("Malformed data length packet. Perhaps connection just closed.")
        return await self._receive(int.from_bytes(data_length, 'big'))
    
    async def close_connection(self):
        self._writer.close()

class Server:
    def __init__(self, config: dict, logger: logging.Logger = base_logger):
        # Initialize logger
        self.logger = logger
        
        # Read config
        self.host = config['host']
        self.port = config['port']

        self.max_num_cached_events_retrials = config['max_num_cached_events_for_retrials']
        self.max_num_cached_events_for_postponement = config['max_num_cached_events_for_postponement']

        self.captcha_enabled = config['register_captcha_enabled']
        self.captcha_digits_num = config['register_captcha_number_of_digits']
        self.captcha_difficulty = config['_register_captcha_difficulty']

        self.pow_alg_enabled = config['register_pow_alg_enabled']
        self.pow_alg_diff = config['register_pow_alg_difficulty']
        self.pow_alg_exdiff = config['register_pow_alg_exdifficulty']
        self.pow_alg_saltlen = config['_register_pow_alg_salt_length']

        self.max_seconds_packet_active = config['_max_seconds_packet_timestamp_active']
        self.max_nonce_list_size = config['_max_nonce_list_size']
        
        # Initialize database
        self.db = Database(logger)
        """Database instance"""
        
        # Initialize events
        self.events = Events((
            #~ Raw data processor
            *(
                'on_netmessage',
            ),

            #~ Authentication processor
            *(
                'on_registration', 'on_registration_confirmation', 'on_authorization'
            ),

            #~ Friend requests
            *(
                'on_friend_request',
            ),

            #~ Transmission requests
            *(
                'on_transmission',
            ),
        ))

        # Initialize peers dictionary
        self.peers = {}
        """Contains information about connected peers, like their auth state."""
        self.peers : dict[Peer, dict]

        # Initialize captcha manager
        self.captcha = CaptchaManager(self.captcha_digits_num, self.captcha_difficulty)

        # Initialize latest nonces list (mitigation of Replay attack)
        self.latest_nonces = []

        self.event(self.on_netmessage)
        self.event(self.on_registration)
        self.event(self.on_registration_confirmation)
        self.event(self.on_authorization)
        self.event(self.on_friend_request)
        self.event(self.on_transmission)

    def event(self, func):
        self.events.handler(func)

    async def on_registration_confirmation(self, peer: Peer, confirmation_packet: RegistrationConfirmation):
        self.logger.info('Received RegistrationConfirmation packet, proceeding...')

        registration_data = self.peers[peer.address]['registration']['data']
        client_user = User(**registration_data['user'])

        if 'registration' not in self.peers[peer.address]:
            self.logger.error("Peer tried to confirm uninitialized registration.")
            await peer.send(
                bytes(RegistrationResult(
                    base64.b64decode(registration_data['user']['public_key']),
                    sender=ServerAccount(),
                    recipient=client_user,
                    message="Peer tried to confirm uninitialized registration."
                ))
            )
            return
        
        if self.peers[peer.address]['registration'] is None:
            self.logger.error("Peer tried to confirm uninitialized registration.")
            await peer.send(
                bytes(RegistrationResult(
                    base64.b64decode(registration_data['user']['public_key']),
                    sender=ServerAccount(),
                    recipient=client_user,
                    message="Peer tried to confirm uninitialized registration."
                ))
            )
            return
        
        confirmation_data = confirmation_packet.data

        captcha_solution = confirmation_data['captcha_solution']
        pow_solution = confirmation_data['proof_of_work_solution']

        if self.captcha_enabled:
            if not captcha_solution:
                self.logger.error("Peer tried to confirm registration without solving Captcha.")
                await peer.send(
                    bytes(RegistrationResult(
                        base64.b64decode(registration_data['user']['public_key']),
                        sender=ServerAccount(),
                        recipient=client_user,
                        message="Peer tried to confirm registration without solving Captcha."
                    ))
                )
                return
            
            if self.peers[peer.address]['registration']['captcha'][0] != captcha_solution:
                self.logger.error("Peer solved captcha incorrectly.")
                await peer.send(
                    bytes(RegistrationResult(
                        base64.b64decode(registration_data['user']['public_key']),
                        sender=ServerAccount(),
                        recipient=client_user,
                        message="Peer solved captcha incorrectly."
                    ))
                )
                return
        
        if self.pow_alg_enabled:
            if not pow_solution:
                self.logger.error("Peer tried to confirm registration without solving Proof-of-Work.")
                await peer.send(
                    bytes(RegistrationResult(
                        base64.b64decode(registration_data['user']['public_key']),
                        sender=ServerAccount(),
                        recipient=client_user,
                        message="Peer tried to confirm registration without solving Proof-of-Work."
                    ))
                )
                return
            
            pow_verification = self.peers[peer.address]['registration']['proof_of_work'].verify_solution(pow_solution)
            if pow_verification[0] != True:
                self.logger.error(f"Peer solved PoW incorrectly: {pow_verification[1]}")
                await peer.send(
                    bytes(RegistrationResult(
                        base64.b64decode(registration_data['user']['public_key']),
                        sender=ServerAccount(),
                        recipient=client_user,
                        message=f"Peer solved PoW incorrectly: {pow_verification[1]}"
                    ))
                )
                return
        
        self.logger.debug("Peer completed registration confirmation, proceeding...")

        try:
            registration_result = self.db.register(client_user)
            registered = isinstance(registration_result, bool)
            await peer.send(
                bytes(RegistrationResult(
                    base64.b64decode(registration_data['user']['public_key']),
                    sender=ServerAccount(),
                    recipient=client_user,
                    message= 'Success!' if registered else str(registration_result[1])
                ))
            )

            if registered:
                self.peers[peer.address]['authorized'] = True
                self.peers[peer.address]['user'] = client_user
                self.peers[peer.address]['peer'] = peer
                self.logger.info('Successfully registered peer!')
        except Exception as e:
            self.logger.info(f'Couldnt register peer:\n{traceback.format_exc()}')
            await peer.send(
                bytes(RegistrationResult(
                    base64.b64decode(registration_data['user']['public_key']),
                    sender=ServerAccount(),
                    recipient=client_user,
                    message='Internal error.'
                ))
            )
    
    async def on_registration(self, peer: Peer, packet: Registration):
        self.logger.info('Received Registration packet, proceeding...')
        self.peers[peer.address]['registration'] = {}
        self.peers[peer.address]['registration']['data'] = packet.data

        self.peers[peer.address]['registration']['captcha'] = self.captcha.generate() if self.captcha_enabled else None
        self.peers[peer.address]['registration']['proof_of_work'] = ProofOfWorkSession(
            self.pow_alg_diff,
            self.pow_alg_exdiff,
            self.pow_alg_saltlen
        ) if self.pow_alg_enabled else None

        captcha_io = BytesIO()
        if self.captcha_enabled:
            self.peers[peer.address]['registration']['captcha'][1].save(captcha_io, format='PNG')

        await peer.send(
            bytes(RegistrationConfirmationRequest(
                base64.b64decode(packet.data['user']['public_key']),
                sender=ServerAccount(),
                recipient=User(**packet.data['user']),
                captcha_image=base64.b64encode(
                    captcha_io.getvalue()
                ).decode() if self.captcha_enabled else None,
                proof_of_work_params=self.peers[peer.address]['registration']['proof_of_work'].params_json if self.pow_alg_enabled else None
            ))
        )
    
    async def on_authorization(self, peer: Peer, packet: Authentication):
        authentication_data = packet.data
        
        self.logger.info('Received Authentication packet, proceeding...')

        if User(**authentication_data['user']) != packet.sender:
            self.logger.error('Peer tried to authenticate as a different user.')
            await peer.send(
                bytes(AuthenticationResult(
                    base64.b64decode(packet.sender.public_key),
                    sender=ServerAccount(),
                    recipient=packet.sender,
                    message='Peer tried to authenticate as a different user.'
                ))
            )
            return
        
        if self.db.fetch_user(userid=packet.sender.userid) is None:
            self.logger.error('User was not found during the authorization process!')
            await peer.send(
                bytes(AuthenticationResult(
                    base64.b64decode(packet.sender.public_key),
                    sender=ServerAccount(),
                    recipient=packet.sender,
                    message='User not found!'
                ))
            )
            return
        
        self.peers[peer.address]['authorized'] = True
        self.peers[peer.address]['user'] = packet.sender
        self.peers[peer.address]['peer'] = peer
        await peer.send(
                bytes(AuthenticationResult(
                    base64.b64decode(packet.sender.public_key),
                    sender=ServerAccount(),
                    recipient=packet.sender,
                    message='Success!'
                ))
            )
        self.logger.info('Successfully authenticated peer.')

    async def on_friend_request(self, sender_peer: Peer, data: bytes):
        self.logger.info("Peer sent friend request to another peer, proceeding...")

        sender_info = self.peers[sender_peer.address]
        event = Event.from_bytes(
            data,
            sender_info['exclusive_keys']['private']
        )
        sender_user = sender_info['user']
        
        for peerAddr, peerInfo in self.peers.items():
            if peerInfo['user'].username == event.data['user']:
                try:
                    await peerInfo['peer'].send(
                        bytes(FriendRequest(
                            peerInfo['packetdsa'],
                            base64.b64decode(peerInfo['user'].public_key),
                            sender=ServerAccount(),
                            recipient=peerInfo['user'],
                            user=sender_user
                        ))
                    )
                    await sender_peer.send(
                        bytes(FriendRequestResult(
                            sender_info['packetdsa'],
                            base64.b64decode(sender_user.public_key),
                            sender=ServerAccount(),
                            recipient=sender_user,
                            fr_eid=event.data['eid'],
                            result=(True, 'Success!')
                        ))
                    )
                    self.logger.info("Successfully transmitted friend request!")
                    return
                except:
                    break
        
        self.logger.error("Peer tried to send friend request to offline or unknown peer!")
        await sender_peer.send(
            bytes(FriendRequestResult(
                sender_info['packetdsa'],
                base64.b64decode(sender_user.public_key),
                sender=ServerAccount(),
                recipient=sender_user,
                fr_eid=event.data['eid'],
                result=(False, 'Requested user not found!')
            ))
        )
    
    async def on_transmission(self, sender_peer: Peer, data: bytes):
        self.logger.info("Peer requested event transmission, proceeding...")

        sender_info = self.peers[sender_peer.address]
        packet = TransmissionRequest.from_bytes(data)
        sender_user = sender_info['user']
        requested_recipient = User(**packet.data['recipient'])

        for peerAddr, peerInfo in self.peers.items():
            if peerInfo['user'].userid == requested_recipient.userid:
                await peerInfo['peer'].send(
                    base64.b64decode(packet.data['data'])
                )
                await sender_peer.send(
                    bytes(TransmissionResult(
                        sender_user,
                        packet.data['eid'],
                        result=(True, 'Success!')
                    ))
                )
                self.logger.info("Successfully transmitted event!")
                return
        
        self.logger.error("Peer tried to send friend request to offline or unknown peer!")
        await sender_peer.send(
            bytes(TransmissionResult(
                sender_user,
                packet.data['eid'],
                result=(False, 'Recipient is unknown or offline!')
            ))
        )

    async def on_netmessage(self, peer: Peer, data: bytes):
        peer_info = self.peers[peer.address]
        if peer_info['authorized']:
            packet_id = int.from_bytes(data[:4], 'big')
            match packet_id:
                case FriendRequest.pId:
                    self.events.on_friend_request(peer, data)
                case TransmissionRequest.pId:
                    self.events.on_transmission(peer, data)
        else:
            packet, nonce, timestamp = SecurePacket.from_bytes(
                data,
                peer_info['exclusive_keys']['private'],
                b'lopuhnet-auth',
                return_nonce_and_timestamp=True
            )

            if nonce in self.latest_nonces:
                self.logger.error("Peer tried to send, or resend a SecurePacket, with known nonce. Might be a Replay attack.")
                return
            
            if time.time() - timestamp > self.max_seconds_packet_active:
                self.logger.error("Peer tried to send, or resend a SecurePacket, with too old timestamp. Might be a Replay attack.")
                return
            
            if len(self.latest_nonces) > self.max_nonce_list_size:
                self.latest_nonces.pop(0)
            self.latest_nonces.append(nonce)

            if packet.pId == Authentication.pId:
                self.events.on_authorization(peer, packet)
            elif packet.pId == Registration.pId:
                self.events.on_registration(peer, packet)
            elif packet.pId == RegistrationConfirmation.pId:
                self.events.on_registration_confirmation(peer, packet)
            else:
                self.logger.error("Received unknown packet from peer. (Before authorization)")

    async def on_connection(self, peer: Peer):
        self.logger.info('Peer connected!')

        self.peers[peer.address] = {'authorized': False}
        
        req = await peer.receive()
        if not req == b'KEYEXCHANGE':
            self.logger.error(f'Expected initial key-exchange request from peer, got unknown (req={req}) one.')
            self.logger.debug('Closing connection!')
            raise RuntimeError("Connection closed due to an internal error.")
        
        exclusive_keys = CHAKEM.generate_keys()
        pdsa = PacketDSA()
        self.peers[peer.address]['exclusive_keys'] = {
            'public': exclusive_keys[0],
            'private': exclusive_keys[1],
        }
        self.peers[peer.address]['packetdsa'] = pdsa
        await peer.send(b'PUBLIC:' + exclusive_keys[0])
        await peer.send(b'PUBLICSIGN:' + pdsa.public)
        
        self.logger.info('Successfully sent public key to newly connected peer!')

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.logger.debug("Handling new client...")

        peer = Peer(reader, writer)
        try:
            await self.on_connection(peer)
        except (OSError, RuntimeError) as e:
            self.logger.error(f"Closing connection due to internal error occurred while processing new connection ({peer.address}):\n{traceback.format_exc()}")
            await peer.close_connection()
            if peer.address in self.peers:
                self.peers.pop(peer.address)
            return
        
        self.logger.debug("Listening peer...")
        
        while True:
            try:
                data = await peer.receive()
            except (OSError, RuntimeError) as e:
                self.logger.info(f"Closing peer's connection due to following error:\n{traceback.format_exc()}")
                if peer.address in self.peers:
                    self.peers.pop(peer.address)
                break
            self.events.on_netmessage(peer, data)

    async def _run(self):
        self.logger.info("Running server...")
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        async with server:
            await server.serve_forever()

    def start(self):
        asyncio.run(self._run())

if __name__ == '__main__':
    s = Server(config=json.load(
        open('config.json', encoding='utf-8')
    ))
    s.start()