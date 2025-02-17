import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

import lnet_events as events
import lnet_types as types

import asyncio
from shared.asyncio_events import Events
from shared.base_logger import logging, base_logger
from shared.dbmanager import Database
from shared.basic_types import User, ServerAccount
from shared.packets import *
from shared.shared_utils import ProofOfWorkSession

import traceback
from types import coroutine
from typing import Optional, Union

import base64
from io import BytesIO
from PIL import Image

from lnet_events import *
from lnet_types import *

class LNetAPI:
    """## LNet API Wrapper"""
    def __init__(
            self,
            server_host: str,
            server_port: int,
            password: str,
            database_path: str = 'lnet.db',
            # autosaver: DataAutoSaver = None,
            # account_data: AccountData = None,
            logger: logging.Logger = base_logger,
            _max_seconds_packet_active: int = 60,
            _max_nonce_list_size: int = 2048
        ):
        """## Create instance of LNet API Wrapper

        Args:
            server_host (str): server's hostname (e.g.: server's IP)
            server_port (int): server's listening port (hint: it's set 9229 by default on server-side)
            database_path (str, optional): specific path to the database file. Defaults to 'lnet.db'.
            autosaver (DataAutoSaver, optional): automatically encrypts AccountData and saves into JSON file each time it gets updated. Recommended to use!. Defaults to None.
            account_data (AccountData, optional): instance of AccountData containing your account's credentials and other data. Defaults to None.
            logger (logging.Logger, optional): custom logger. Defaults to base_logger.
        """

        # Configure server address
        self.server_host = server_host
        self.server_port = server_port
        
        # Initialize events and logger
        self.events = Events((
            #~ Low-level transport events
            *(
                'on_netmessage', 'on_netevent'
            ),

            #~ Specifically API Client events
            *(
                'on_start', 'on_registration_captcha', 'on_ready',
            ),

            #~ Friend requests events
            *(
                'on_friend_request', 'on_friend_request_accepted', 'on_friend_removed'
            ),

            #~ Group events
            *(
                'on_group_created', 'on_group_deleted'
            ),

            #~ Messages managing events
            *(
                'on_message', 'on_message_edit', 'on_message_delete',
            ),
        ))
        """
        List of API events that wrapper fires when they happen.
        Example usage:
        ```
        @client.event
        async def on_ready():
            client.logger.info("Client is ready!")
        ```

        Breakdown of available useful events:
          - on_start (required): when client starts; in this event you must register or authorize via server.
          - on_registration_captcha (required): if server is configured so, it requires from you to solve a captcha, so you have to handle this event.
          - on_ready: after successful authorization and readiness to receive data.
          - on_friend_request: after receiving a friend request.
          - on_friend_request_accepted: after someone accepted your friend request.
          - on_friend_removed: after friend has been removed from your friend list.
          - on_group_created: after a group was made.
          - on_group_deleted: after a group has been deleted.
          - on_message: after receiving a message.
          - on_message_edit: after someone edited their message.
          - on_message_delete: after someone deleted their message.
        """
        self.logger = logger
        """LNet Client logger"""

        # Initialize DB
        self._database = Database(logger, password, database_path)
        """Client-side database instance"""

        # Initialize user data
        self._public_key = None
        self._private_key = None
        self._pdsa = None
        self._server_public = None
        self._server_sign_public = None

        self.friends = None
        # self._groups = None

        # Read user data
        account_user = self._database.get_client_account()
        if account_user:
            safe_user = User(**account_user.__dict__)
            safe_user.private_key = ''
            safe_user.private_signkey = ''

            self.user = safe_user
            """Self `User` instance"""
            self._pdsa = PacketDSA(
                base64.b64decode(account_user.public_signkey),
                base64.b64decode(account_user.private_signkey),
            )
            self._private_key = base64.b64decode(account_user.private_key)
            self._public_key = base64.b64decode(account_user.public_key)
            self.friends = self._database.get_client_friends()
            # self._groups = account_user.groups
        else:
            self._pdsa = PacketDSA()
            self._public_key, self._private_key = CHAKEM.generate_keys()
        
        self.authorized = False
        """Sets to `True` after successful authorization (or registration)."""

        # Autosave configuration
        # self.autosaver = autosaver
        # """Configured `DataAutoSaver` instance"""
        # self.autosave_enabled = autosave_data
        # self.autosave_path = autosave_path

        # Replay attack mitigation configuration
        self._max_seconds_packet_active = _max_seconds_packet_active
        self._max_nonce_list_size = _max_nonce_list_size
        # Initialize latest nonces list (mitigation of Replay attack)
        self.latest_nonces = []

        # Socket stuff
        self._running = False
        self._writer = None
        self._reader = None

        # Initialize dictionaries, containing some data that needs to be temporary cached
        self._transmission_results = {}
        self._frequests = {}
        self._statuses = {}
        self._captcha_solution = None

        # Initialize on_netmessage event
        self.event(self.on_netmessage)
        self.event(self.on_netevent)

    def event(self, func):
        """Decorator for event-handling functions.

        Args:
            func (function): a coroutine-like function
        
        Example:
        ```
        @client.event
        async def on_ready():
            client.logger.debug("Client is ready!")
        ```
        """
        self.events.handler(func)

    async def _send(self, data: bytes):
        """Send bytes to server

        Args:
            data (bytes): data to send
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
        """Await bytes from server.

        Returns:
            bytes: received data
        """
        data_length = await self._reader.read(4) # Read data length
        return await self._receive(int.from_bytes(data_length, 'big'))

    async def close_connection(self):
        """Close connection with the server.
        """
        self._writer.close()
        await self._writer.wait_closed()

    def _get_avatar_seed(self, seed: str) -> int:
        """Return avatar seed as an integer.

        Args:
            seed (str): seed-phrase

        Returns:
            int: seed represented as integer
        """
        return xxhash.xxh128(seed).intdigest() % (10 ** 10)

    async def authorize(self):
        """Authorize currently loaded user.

        Raises:
            RuntimeError: if have been authorized already.
            RuntimeError: if no account credentials given.
            RuntimeError: if error occurrs during authorization.

        Returns:
            tuple[bool, str]: result
        """
        self.logger.info(f"Requesting authentication...")

        if self.authorized:
            raise RuntimeError("Already authorized!")

        if not hasattr(self, 'user'):
            raise RuntimeError("No account found to authenticate!")
        
        if self.user is None:
            raise RuntimeError("No account found to authenticate!")

        await self._send(
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
                b'lopuhnet-auth',
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

    async def solve_captcha(self, answer: str):
        """Provide the answer to currently processing registration captcha.

        Args:
            answer (str): captcha solution (e.g.: 1234)
        """
        self._captcha_solution = answer

    async def register(self, name: str, username: str, avatar_seed: str):
        """Registers user and saves all credentials.

        Args:
            name (str): user's display name
            username (str): user's unique username
            avatar_seed (str): user's avatar seed

        Raises:
            RuntimeError: if have been authorized already.

        Returns:
            tuple[bool, str]: result
        """
        self.logger.info("Registrating user...")

        if self.authorized:
            raise RuntimeError("Already authorized!")
        
        public_key_enc = base64.b64encode(self._public_key).decode()
        public_signkey_enc = base64.b64encode(self._pdsa.public).decode()
        user = User(name, username, self._get_avatar_seed(avatar_seed), public_key_enc, public_signkey_enc)

        self.logger.debug("Sending Registration packet...")
        await self._send(
            bytes(Registration(
                self._pdsa,
                self._server_public,
                sender=user,
                recipient=ServerAccount(),
                user=user
            ))
        )

        try:
            reg_confirm_data = SecurePacket.from_bytes(
                (await self.receive()),
                self._private_key,
                b'lopuhnet-auth',
                _verify_signature=False
            ).data
        except:
            self.logger.error('RegistrationConfirmationRequest packet decryption error, might be a packet mismatch.')
            return False, 'Expected RegistrationResultRequest packet from server, got unknown one.'
        
        self.logger.debug("Processing RegistrationConfirmationRequest packet...")

        proof_of_work = ProofOfWorkSession.solve(
                b'Your name here. To be serious, you can implement anything you want here.',
                reg_confirm_data['proof_of_work_params']
        ) if reg_confirm_data['proof_of_work_params'] else None

        if reg_confirm_data['captcha_image']:
            self._captcha_solution = None
            captcha_image = Image.open(BytesIO(
                base64.b64decode(reg_confirm_data['captcha_image'])
            ))
            self.events.on_registration_captcha(captcha_image)
            self.logger.debug("Awaiting user's interaction - captcha solution...")

            while self._captcha_solution is None:
                await asyncio.sleep(.1)
        
        await self._send(
            bytes(RegistrationConfirmation(
                self._pdsa,
                self._server_public,
                sender=user,
                recipient=ServerAccount(),
                captcha_solution=self._captcha_solution,
                proof_of_work_solution=proof_of_work
            ))
        )

        try:
            registration_result = SecurePacket.from_bytes(
                (await self.receive()),
                self._private_key,
                b'lopuhnet-auth',
                _verify_signature=False
            ).data
        except:
            self.logger.error('RegistrationResult packet decryption error, might be a packet mismatch.')
            return False, 'Expected RegistrationResult packet from server, got unknown one.'

        if registration_result['message'] == 'Success!':
            self.logger.info("Successfully registered! Saving all the data...")

            self.user = user
            self.authorized = True
            self.friends = {}
            # self._groups = {}

            account_user = User(**user.__dict__)
            account_user.private_key = base64.b64encode(self._private_key).decode()
            account_user.private_signkey = base64.b64encode(self._pdsa.private).decode()
            self._database.register(account_user)
            
            self.logger.info("Ready to use!")
            return True, 'Ready to use!'
        
        self.logger.error(f"Considering server's response it's registration failure: {registration_result['message']}")
        return False, registration_result['message']

    async def _connect(self):
        """Open connection to LNet Server.
        """
        self.logger.info(f"Connecting to {self.server_host}:{self.server_port}")
        # self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self._sock.connect((self.server_host, self.server_port))
        self._reader, self._writer = await asyncio.open_connection(
            self.server_host, self.server_port
        )
        self.logger.info("Connected to server")

    async def _fetch_server_key(self):
        """Fetch LNet Server's individual key.
        """
        self.logger.debug(f"Requesting server's individual encryption key...")
        await self._send(b'KEYEXCHANGE')
        self._server_public = (await self.receive())[7:]
        self._server_sign_public = (await self.receive())[11:]
        self.logger.info("Saved server's personal one-time individual encryption key!")

    async def _run(self):
        # if self.autosaver:
        #     await self.autosaver.start()

        #     if not hasattr(self, 'user'):
        #         try:
        #             account_data = AccountData.from_autosave(self.autosaver)
        #             self.user = account_data.user
        #             self._pdsa = account_data.pdsa
        #             self._private_key = account_data.private_key
        #             self._public_key = account_data.public_key
        #             self._friends = account_data.friends
        #             self._groups = account_data.groups
        #         except Exception as e:
        #             self.logger.warning(f"Error occured while reading auto-save file:\n{e}.\n If this happened meanwhile you were not registered, or if you were doing the registration process, then ignore this.")

        try:
            await self._connect()
        except:
            self.logger.error(f"Error occurred while opening connection to the server:\n{traceback.format_exc()}")
            return
        await self._fetch_server_key()

        self._running = True
        self.events.on_start()

        await self._listen_netmessages()

    async def send_friend_request(self, username: str):
        """Send friend request to the peer with given username.

        Args:
            username (str): peer with this username

        Returns:
            tuple[bool, str]: result, result message
        """

        self.logger.debug(f'Sending a friend request to {username}...')
        
        ev = FriendRequest(
            self._pdsa,
            self._server_public,
            sender=self.user,
            recipient=ServerAccount(),
            user=username
        )
        self._frequests[ev.eid] = None
        await self._send(bytes(ev))

        self.logger.debug('Waiting answer from server...')
        timeout = time.time() + 5
        while self._frequests[ev.eid] is None:
            if time.time() > timeout:
                self.logger.error('Friend request response time out.')
                self._frequests.pop(ev.eid)
                return False, 'Time out.'
            await asyncio.sleep(.1)
        
        if self._frequests[ev.eid][0] == True:
            self.logger.debug('Friend request sent.')
            self._frequests.pop(ev.eid)
            return True, 'Friend request sent successfully!'
        
        error_message = self._frequests[ev.eid][1]
        self.logger.error(f'Friend request failure: {error_message}.')
        self._frequests.pop(ev.eid)
        return False, error_message
    
    async def accept_friend_request(self, request_sender: User):
        await self._on_friend_registry(request_sender)
        server_response = await self._send_event(
            events.FriendAccepted(
                self._pdsa,
                base64.b64decode(request_sender.public_key),
                sender=self.user,
                recipient=request_sender
            )
        )
        return server_response
    
    async def remove_friend(self, userid: str):
        await self._on_friend_removal(userid)
        return True, 'Removed friend successfully.'
    
    async def _send_event(self, ev: Event):
        """Request event transmission via LNet Server.

        Args:
            ev (Event): event you need to transmit to someone

        Returns:
            tuple[bool, str]: result, result message
        """

        self.logger.debug(f'Requesting a transmission of event (eid={ev.eid})...')
        
        transmission_packet = TransmissionRequest(
            sender=self.user,
            recipient=ev.recipient,
            event=ev
        )
        self._transmission_results[ev.eid] = None
        await self._send(bytes(transmission_packet))

        self.logger.debug('Waiting answer from server...')
        timeout = time.time() + 5
        while self._transmission_results[ev.eid] is None:
            if time.time() > timeout:
                self.logger.error('Transmission request response time out.')
                self._transmission_results.pop(ev.eid)
                return False, 'Time out.'
            await asyncio.sleep(.1)
        
        if self._transmission_results[ev.eid][0] == True:
            self.logger.debug('Transmission succeed.')
            self._transmission_results.pop(ev.eid)
            if EventFlags.DISPOSABLE.name not in EventFlags.get_flags(ev.flags):
                # encrypted_event = await self.autosaver.encrypt_event(bytes(ev))
                self._database.add_event(time.time_ns(), ev.recipient.userid, ev, ev.eid)
            return True, 'Success!'
        
        error_message = self._transmission_results[ev.eid][1]
        self.logger.error(f'Transmission request failure: {error_message}.')
        self._transmission_results.pop(ev.eid)
        return False, error_message

    async def send_message(self, message: types.Message) -> Union[bool, tuple[bool, str]]:
        """Send message to channel.

        Dev-note: message timestamps beyond this client's side.
        It means recipient(-s) will automatically handle the timestamp parameter.
        As a result, you can ignore timestamp field while sending the message.

        Args:
            message (Message): message you want send to

        Returns:
        - if sent in DM:
            result (tuple[True, ''] | tuple[False, str]): true if success, otherwise false and error message
        - if sent in Group
            result (tuple[True, '', accepted_users] | tuple[False, str]): true if success, otherwise false; error message; users that received message successfully
        """
        
        if not self.authorized:
            raise RuntimeError("Unauthorized.")

        if not message.author == self.user:
            raise RuntimeError("Message author does not equal to client's account user. Not authorized properly or fake message.")

        if len(message.content) > 4000:
            raise RuntimeError("Message content is too large!")
        
        if len(message.content) == 0 and len(message.pictures) == 0:
            raise RuntimeError("Message must have content or attached pictures in it.")
        
        found_user = await self.fetch_user(message.channel)

        if found_user:
            recipient = found_user
            # self._check_peer_status(recipient)
            result = await self._send_event(
                ev = events.MsgCreated(
                    self._pdsa,
                    base64.b64decode(recipient.public_key),
                    sender=self.user,
                    recipient=recipient,
                    message=message
                )
            )
            if result[0] == True:
                self.events.on_message(message)
        
        else:
            raise RuntimeError("Message channel is invalid. Note that message channel must be an ID of a group or a person (DM).")
        
        return result

    async def _listen_netmessages(self):
        while not self.authorized:
            await asyncio.sleep(.1)
        
        self.events.on_ready()
        self.logger.debug("Running message listener...")

        while self._running:
            try:
                data = await self.receive()
                if not data:
                    if not self._running:
                        break
                    continue
                self.events.on_netmessage(data)
            except Exception as e:
                self.logger.fatal(f"Error in listening loop: {e}")
                break
    
    async def on_netmessage(self, data: bytes):
        # As this event is being fired only after authorization,
        # that means we can decrypt each packet as an Event

        epId = int.from_bytes(data[:4], 'big')
        if epId == TransmissionResult.pId:
            event = TransmissionResult.from_bytes(data)
        else:
            is_server_packet = epId in (FriendRequest.pId, FriendRequestResult.pId)
            event, nonce, timestamp = Event.from_bytes(
                data,
                self._private_key,
                self._server_sign_public if is_server_packet else None,
                return_nonce_and_timestamp=True
            )

            if nonce in self.latest_nonces:
                self.logger.error("Received `Event`, with known nonce. Might be a Replay attack.")
                return
            
            if time.time() - timestamp > self._max_seconds_packet_active:
                self.logger.error("Received `Event`, with too old timestamp. Might be a Replay attack.")
                return
            
            if len(self.latest_nonces) > self._max_nonce_list_size:
                self.latest_nonces.pop(0)
            self.latest_nonces.append(nonce)
        
        match event.pId:
            case FriendRequest.pId:
                self.events.on_friend_request(User(**event.data['user']))
            case FriendRequestResult.pId:
                self._frequests[event.data['request_eid']] = event.data['result']
            case TransmissionResult.pId:
                self._transmission_results[event.data['eid']] = event.data['result']
            case events.FriendAccepted.pId:
                await self._on_friend_registry(event.sender)
            case _:
                self.events.on_netevent(data, event)
    
    async def on_netevent(self, original_data: bytes, event: Event):
        match event.pId:
            case events.MsgCreated.pId:
                msg = types.Message(**event.data['message'])
                msg.author = User(**msg.author)
                if not msg.author == event.sender:
                    self.logger.warning("Peer sent MsgCreated with insufficient permissions.")
                    return
                
                msg.timestamp = time.time()
                msg.content = msg.content[:4000]
                if len(msg.content) == 0 and len(msg.pictures) == 0:
                    self.logger.warning("Peer sent empty Message in MsgCreated.")
                    return
                
                pics = msg.pictures.copy()
                msg.pictures.clear()
                for pic in pics:
                    msg.pictures.append(types.Picture(**pic))
                
                self._database.add_event(time.time_ns(), event.recipient.userid, event, event.eid)
                self.events.on_message(msg)
            case _:
                # self.logger.debug(event.data)
                self.logger.error("Received Event with unknown pId. Skipping...")

    # @property
    # def friends(self) -> list[User]:
    #     """Retrieve User instances from the saved friend list.

    #     Returns:
    #         list[User]: list of User instances
    #     """
    #     return [User(**friend_data) for friend_data in self._friends.values()]
    
    async def fetch_user(self, userid: str = None, username: str = None) -> Optional[User]:
        """Fetch specific User by given parameters. (from friend list)

        Args:
            userid (str, optional)
            username (str, optional)

        Returns:
            Optional[User]: fetched User or None
        """
        
        for user in self.friends:
            if user.username == username or user.userid == userid:
                return user
        
        return None
    
    # async def fetch_group(self, groupid: str = None, group_name: str = None) -> Optional[types.Group]:
    #     """Fetch specific Group by given parameters.

    #     Args:
    #         groupid (str, optional)
    #         groupname (str, optional)

    #     Returns:
    #         Optional[Group]: fetched Group or None
    #     """

    #     if groupid:
    #         group = types.Group(**self._groups[groupid])
    #         group.members = [User(**m) for m in group.members]
    #         return group
        
    #     for group in self._groups.values():
    #         if group['name'] == group_name:
    #             group = types.Group(**group)
    #             group.members = [User(**m) for m in group.members]
    #             return group
        
    #     return None

    # @property
    # def groups(self) -> list[types.Group]:
    #     """Retrieive Group instances from the saved group list.

    #     Returns:
    #         list[Group]: list of Group instances
    #     """
    #     return [types.Group(**group_data) for group_data in self._groups.values()]

    async def _on_friend_registry(self, user: User):
        self.friends.append(user)
        self._database.register(user)
        
        self.events.on_friend_request_accepted(user)
    
    async def _on_friend_removal(self, userid: str):
        friend = None

        for f in self.friends:
            if f.userid == userid:
                friend = f
                self.friends.remove(f)
                break
        
        self._database.remove_user(userid)
        
        if friend:
            self.events.on_friend_removed(friend)
    
    async def _on_group_registry(self, group: types.Group):
        self._groups[group.groupid] = group
        if self.autosaver:
            await self.autosaver.add_group(group)
    
    async def _on_group_removal(self, groupid: str):
        if groupid in self._groups:
            self._groups.pop(groupid)
        
        if self.autosaver:
            await self.autosaver.remove_group(groupid)

    async def stop(self):
        """Stops the LNet Client
        """
        self._running = False
        await self.close_connection()
        self.logger.info("Connection closed")

    def start(self):
        """Starts the LNet Client
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._run())
        except Exception as e:
            # traceback.print_exc()
            asyncio.run(self._run())