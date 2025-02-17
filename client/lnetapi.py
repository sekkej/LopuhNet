# import logging
# from typing import Coroutine
# from colorlog import ColoredFormatter
# from events import Events
# import traceback
# from client import Client
# import json
# from lnet_types import *
# from lnet_events import *
# import base64
# from threading import Thread
# import asyncio

# class LNetEvents(Events):
#     __events__ = (
#         'on_start',
#         'on_friend_request', 'on_friend_accepted',
#         'on_typing',
#         'on_message', 'on_message_edit', 'on_message_delete',
#         'on_group_created'
#     )

# class LNet:
#     def __init__(self):
#         self.events = LNetEvents()
#         log_format = (
#             '%(asctime)s '
#             '%(log_color)s'
#             '%(levelname)-8s'
#             '%(reset)s '
#             '%(message)s'
#         )

#         formatter = ColoredFormatter(
#             log_format,
#             datefmt='%Y-%m-%d %H:%M:%S',
#             reset=True,
#             log_colors={
#                 'DEBUG': 'cyan',
#                 'INFO': 'green',
#                 'WARNING': 'yellow',
#                 'ERROR': 'red',
#                 'CRITICAL': 'red,bg_white',
#             }
#         )

#         handler = logging.StreamHandler()
#         handler.setFormatter(formatter)

#         self.logger = logging.getLogger(__name__)
#         self.logger.setLevel(logging.DEBUG)
#         self.logger.addHandler(handler)

#         self.client = None
#         """LNet client. **Use only if you know what are you doing!**"""
#         self.__running = True
#         self.user = None
#         """Current user instance"""
    
#     def stop(self):
#         self.__running = False

#     def start(self, trusted_consts: str, cached_data: str, database_filename: str='lnet', _run_until_stopped=True):
#         """Starts the LNet instance

#         Args:
#             trusted_consts (str): path to JSON containing constants like server IP and port
#             cached_data (str): path to JSON containing cached user's data
#         """

#         self.client = Client(
#             self.logger,
#             self.events,
#             json.load(open(trusted_consts, encoding='utf-8')),
#             cached_data,
#             database_filename
#         )
#         self.client.start()

#         self.events.on_start()
#         if _run_until_stopped:
#             while self.__running:
#                 continue
    
#     def register(self, name: str, username: str, avatar_seed: str):
#         """Registers yourself.

#         Args:
#             name (str): your display name
#             username (str): your username
#             avatar_seed (str): any string you like. UIs must show avatars generated from this seed

#         Returns:
#             result (True | tuple[False, str]): true if success, otherwise false and error message
#         """
#         registration_result = self.client.register(
#             name,
#             username,
#             avatar_seed
#         )
#         if isinstance(registration_result, bool) and registration_result == True:
#             self.user = self.client.account
#         return registration_result
    
#     def authorize(self):
#         """Authorizes yourself.

#         Returns:
#             result (True | tuple[False, str]): true if success, otherwise false and error message
#         """
#         authorization_result = self.client.authenticate()
#         if isinstance(authorization_result, bool) and authorization_result == True:
#             self.user = self.client.account
#         return authorization_result
    
#     def event(self, func: 'function'|Coroutine):
#         """Built-in event handler

#         Args:
#             func (function): handler of an event (function's name must be the same as event's name)
#         """

#         def error_handled_func(*args, **kwargs):
#             try:
#                 if asyncio.iscoroutinefunction(func):
#                     try:
#                         asyncio.get_event_loop().run_until_complete(func(*args, **kwargs))
#                     except:
#                         asyncio.new_event_loop().run_until_complete(func(*args, **kwargs))
#                 else:
#                     func(*args, **kwargs)
#             except:
#                 self.logger.error(traceback.format_exc())
#         self.events.__getattr__(func.__name__).targets.append(error_handled_func)

#     def _check_authorization(self):
#         """Checks if you're authorized"""
#         if not isinstance(self.user, User):
#             raise RuntimeError("Unauthorized.")
    
#     def _check_peer_status(self, peer: User):
#         """Tries to send CheckStatus event to the peer"""
#         if self.client.check_peer_status(peer.userid) != True:
#             raise RuntimeError("Requested peer is offline.")

#     def send_friend_request(self, username: str):
#         """Sends friend request to the user with given username

#         Args:
#             username (str): requested user's username

#         Returns:
#             result (True | tuple[False, str]): true if success, otherwise false and error message
#         """
#         self._check_authorization()
#         return self.client.send_friend_request(username)

#     def accept_friend_request(self, friend: User):
#         """Accepts friend request

#         Args:
#             friend (User): friend (User): friend's User instance that you might have from on_friend_request event

#         Returns:
#             result (True | tuple[False, str]): true if success, otherwise false and error message
#         """
#         self._check_authorization()

#         self.client.add_friend(friend)
#         return self.client.send_event(FriendAccepted(
#             self.client.pdsa,
#             base64.b64decode(friend.public_key),
#             sender=self.user,
#             recipient=friend,
#         ))
    
#     def fetch_user(self, userid: str = None, username: str = None) -> (User | None):
#         if userid:
#             return User(**self.client.friends[userid])
        
#         for user in self.client.friends.values():
#             if user['username'] == username:
#                 return User(**user)
        
#         return None
    
#     def fetch_group(self, groupid: str = None, group_name: str = None) -> (Group | None):
#         if groupid:
#             group = Group(**self.client.groups[groupid])
#             group.members = [User(**m) for m in group.members]
#             return group
        
#         for group in self.client.groups.values():
#             if group['name'] == group_name:
#                 group = Group(**group)
#                 group.members = [User(**m) for m in group.members]
#                 return group
        
#         return None

#     def fetch_messages(self, recipients_ids: list[str], index: int = 0):
#         events = self.client.db.get_50_events([self.user.userid, *recipients_ids], index)
#         messages = []
#         for event in events:
#             print(Event.from_bytes(event[1], self.client.private_key).data)
#         return messages

#     def inform_typing(self, peer: User):
#         """Informs interlocutor that you're typing a message right now

#         Args:
#             peer (User): interlocutor that needs to be informed

#         Returns:
#             result (True | tuple[False, str]): true if success, otherwise false and error message
#         """
#         return self.client.send_event(Typing(
#             self.client.pdsa,
#             base64.b64decode(peer.public_key),
#             sender=self.client.account,
#             recipient=[peer]
#         ))

#     def send_message(self, message: Message):
#         """Sends message to a channel

#         Dev-note: message timestamps beyond this client's side
#         It means recipient(-s) that receive your message will automatically handles timestamp parameter
#         As a result, you can ignore timestamp field while sending the message

#         Args:
#             message (Message): message you want send to

#         Returns:
#             result (True | tuple[False, str]): true if success, otherwise false and error message
#         """
        
#         self._check_authorization()

#         if not message.author == self.user:
#             raise RuntimeError("Message author does not equal to client's account user. Not authorized properly or fake message.")

#         if len(message.content) > 4000:
#             raise RuntimeError("Message content is too large!")
        
#         if len(message.content) == 0 and len(message.pictures) == 0:
#             raise RuntimeError("Message must have content or attached pictures in it.")
        
#         # Dev-note: message timestamps beyond this client's side
#         # It means recipient(-s) that receive your message will automatically handles timestamp parameter
#         # As a result, you can ignore timestamp field while sending the message

#         if message.channel in self.client.friends:
#             recipient = self.fetch_user(message.channel)
#             self._check_peer_status(recipient)
#             result = self.client.send_event(MsgCreated(
#                 self.client.pdsa,
#                 base64.b64decode(recipient.public_key),
#                 sender=self.client.account,
#                 recipient=recipient,
#                 message=message
#             ))
#             if result == True:
#                 Thread(target=self.events.on_message, args=(message,)).start()
        
#         elif message.channel in self.client.groups:
#             group = self.fetch_group(message.channel)
#             accepted_peers = []

#             members_without_self = group.members.copy()
#             members_without_self.remove(self.user)

#             for member in members_without_self:
#                 result = self.client.send_event(MsgCreated(
#                     self.client.pdsa,
#                     base64.b64decode(member.public_key),
#                     sender=self.client.account,
#                     recipient=member,
#                     message=message
#                 ))
#                 if isinstance(result, bool) and result == True:
#                     accepted_peers.append(member)
            
#             if len(accepted_peers) == 0:
#                 raise RuntimeError("All members are offline, hence cannot send the message.")
            
#             Thread(target=self.events.on_message, args=(message,)).start()
#             return True, accepted_peers
        
#         else:
#             raise RuntimeError("Message channel is invalid. Note that message channel must be an ID of a group or a person (DM).")
        
#         return result
    
#     def create_group(self, group: Group):
#         self._check_authorization()

#         if len(group.name) == 0:
#             raise RuntimeError("Group's name cannot be empty.")
        
#         if len(group.name) > 64:
#             raise RuntimeError("Group's name is too large.")
        
#         if self.user not in group.members:
#             raise RuntimeError("You must be in Group too!")
        
#         if len(group.members) < 3:
#             raise RuntimeError("Group cannot have less than 2 members.")

#         if len(group.members) > 10:
#             raise RuntimeError("Group cannot have more than 10 members.")

#         accepted_peers = []

#         members_without_self = group.members.copy()
#         members_without_self.remove(self.user)

#         for member in members_without_self:
#             result = self.client.send_event(GroupCreated(
#                 self.client.pdsa,
#                 base64.b64decode(member.public_key),
#                 sender=self.client.account,
#                 recipient=member,
#                 group=group
#             ))
#             if isinstance(result, bool) and result == True:
#                 accepted_peers.append(member)
        
#         if len(accepted_peers) == 0:
#             raise RuntimeError("All members are offline, hence cannot create the group.")
        
#         group.members = accepted_peers
#         group.members.append(self.user)
#         self.client.add_group(group)
#         Thread(target=self.events.on_group_created, args=(group,)).start()

#         return True, accepted_peers

import logging
from typing import Coroutine, List, Union, Optional
from colorlog import ColoredFormatter
import traceback
from client import Client
import json
from lnet_types import *
from lnet_events import *
import base64
import asyncio

class LNetEvents:
    events = (
        'on_start',
        'on_friend_request', 'on_friend_accepted',
        'on_typing',
        'on_message', 'on_message_edit', 'on_message_delete',
        'on_group_created'
    )

class LNet:
    def __init__(self):
        self.events = {ev: [] for ev in LNetEvents.events}
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

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(handler)

        self.client = None
        """LNet client. **Use only if you know what are you doing!**"""
        self.__running = True
        self.user = None
        """Current user instance"""

        self._loop = None
        """Asyncio loop"""
    
    async def stop(self):
        self.__running = False

    async def _run(self, trusted_consts: str, cached_data: str, database_filename: str='lnet', _run_until_stopped=True):
        self.client = Client(
            self.logger,
            self._fire_event,
            json.load(open(trusted_consts, encoding='utf-8')),
            cached_data,
            database_filename
        )
        self.client.start()

        self._fire_event('on_start')
        # if _run_until_stopped:
        #     while self.__running:
        #         await asyncio.sleep(1)  # Sleep to prevent busy-waiting

    def start(self, trusted_consts: str, cached_data: str, database_filename: str='lnet', _run_until_stopped=True):
        """Starts the LNet instance

        Args:
            trusted_consts (str): path to JSON containing constants like server IP and port
            cached_data (str): path to JSON containing cached user's data
        """
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._run(trusted_consts, cached_data, database_filename, _run_until_stopped))
    
    async def register(self, name: str, username: str, avatar_seed: str) -> Union[bool, tuple[bool, str]]:
        """Registers yourself.

        Args:
            name (str): your display name
            username (str): your username
            avatar_seed (str): any string you like. UIs must show avatars generated from this seed

        Returns:
            result (True | tuple[False, str]): true if success, otherwise false and error message
        """
        registration_result = self.client.register(
            name,
            username,
            avatar_seed
        )
        if isinstance(registration_result, bool) and registration_result == True:
            self.user = self.client.account
        return registration_result
    
    async def authorize(self) -> Union[bool, tuple[bool, str]]:
        """Authorizes yourself.

        Returns:
            result (True | tuple[False, str]): true if success, otherwise false and error message
        """
        authorization_result = self.client.authenticate()
        if isinstance(authorization_result, bool) and authorization_result == True:
            self.user = self.client.account
        return authorization_result
    
    def event(self, func: Coroutine):
        """Built-in event handler

        Args:
            func (function): handler of an event (function's name must be the same as event's name)
        """

        async def error_handled_func(*args, **kwargs):
            try:
                await func(*args, **kwargs)
            except:
                self.logger.error(traceback.format_exc())
        self.events[func.__name__].append(error_handled_func)
        return error_handled_func

    def _fire_event(self, event_name: str, *args, **kwargs):
        """Fires an event from outside the running event loop

        Args:
            event_name (str): name of the event to fire
            *args: positional arguments to pass to the event handlers
            **kwargs: keyword arguments to pass to the event handlers
        """
        if event_name not in self.events:
            self.logger.error(f"Event '{event_name}' not found.")
            return

        if self._loop.is_running():
            print(event_name)
            print(self.events[event_name])
            for handler in self.events[event_name]:
                self._loop.create_task(handler(*args, **kwargs))
            # self._loop.call_soon_threadsafe(self._loop.create_task, call_event_handlers())
            # asyncio.ensure_future(call_event_handlers(), loop=self._loop)
            # asyncio.to_thread()
        else:
            self.logger.error("Event loop is not running.")

    def _check_authorization(self):
        """Checks if you're authorized"""
        if not isinstance(self.user, User):
            raise RuntimeError("Unauthorized.")
    
    def _check_peer_status(self, peer: User):
        """Tries to send CheckStatus event to the peer"""
        if self.client.check_peer_status(peer.userid) != True:
            raise RuntimeError("Requested peer is offline.")

    async def send_friend_request(self, username: str) -> Union[bool, tuple[bool, str]]:
        """Sends friend request to the user with given username

        Args:
            username (str): requested user's username

        Returns:
            result (True | tuple[False, str]): true if success, otherwise false and error message
        """
        self._check_authorization()
        return self.client.send_friend_request(username)

    async def accept_friend_request(self, friend: User) -> Union[bool, tuple[bool, str]]:
        """Accepts friend request

        Args:
            friend (User): friend's User instance that you might have from on_friend_request event

        Returns:
            result (True | tuple[False, str]): true if success, otherwise false and error message
        """
        self._check_authorization()

        self.client.add_friend(friend)
        return self.client.send_event(FriendAccepted(
            self.client.pdsa,
            base64.b64decode(friend.public_key),
            sender=self.user,
            recipient=friend,
        ))
    
    async def fetch_user(self, userid: str = None, username: str = None) -> Optional[User]:
        if userid:
            return User(**self.client.friends[userid])
        
        for user in self.client.friends.values():
            if user['username'] == username:
                return User(**user)
        
        return None
    
    async def fetch_group(self, groupid: str = None, group_name: str = None) -> Optional[Group]:
        if groupid:
            group = Group(**self.client.groups[groupid])
            group.members = [User(**m) for m in group.members]
            return group
        
        for group in self.client.groups.values():
            if group['name'] == group_name:
                group = Group(**group)
                group.members = [User(**m) for m in group.members]
                return group
        
        return None

    async def fetch_messages(self, recipients_ids: List[str], index: int = 0) -> List[Message]:
        events = self.client.db.get_50_events([self.user.userid, *recipients_ids], index)
        messages = []
        for event in events:
            print(Event.from_bytes(event[1], self.client.private_key).data)
        return messages

    async def inform_typing(self, peer: User) -> Union[bool, tuple[bool, str]]:
        """Informs interlocutor that you're typing a message right now

        Args:
            peer (User): interlocutor that needs to be informed

        Returns:
            result (True | tuple[False, str]): true if success, otherwise false and error message
        """
        return self.client.send_event(Typing(
            self.client.pdsa,
            base64.b64decode(peer.public_key),
            sender=self.client.account,
            recipient=[peer]
        ))

    async def send_message(self, message: Message) -> Union[bool, tuple[bool, str]]:
        """Sends message to a channel

        Dev-note: message timestamps beyond this client's side
        It means recipient(-s) that receive your message will automatically handles timestamp parameter
        As a result, you can ignore timestamp field while sending the message

        Args:
            message (Message): message you want send to

        Returns:
            result (True | tuple[False, str]): true if success, otherwise false and error message
        """
        
        self._check_authorization()

        if not message.author == self.user:
            raise RuntimeError("Message author does not equal to client's account user. Not authorized properly or fake message.")

        if len(message.content) > 4000:
            raise RuntimeError("Message content is too large!")
        
        if len(message.content) == 0 and len(message.pictures) == 0:
            raise RuntimeError("Message must have content or attached pictures in it.")
        
        if message.channel in self.client.friends:
            recipient = await self.fetch_user(message.channel)
            self._check_peer_status(recipient)
            result = self.client.send_event(MsgCreated(
                self.client.pdsa,
                base64.b64decode(recipient.public_key),
                sender=self.client.account,
                recipient=recipient,
                message=message
            ))
            if result == True:
                self._fire_event('on_message', message)
        
        elif message.channel in self.client.groups:
            group = await self.fetch_group(message.channel)
            accepted_peers = []

            members_without_self = group.members.copy()
            members_without_self.remove(self.user)

            for member in members_without_self:
                result = self.client.send_event(MsgCreated(
                    self.client.pdsa,
                    base64.b64decode(member.public_key),
                    sender=self.client.account,
                    recipient=member,
                    message=message
                ))
                if isinstance(result, bool) and result == True:
                    accepted_peers.append(member)
            
            if len(accepted_peers) == 0:
                raise RuntimeError("All members are offline, hence cannot send the message.")
            
            self._fire_event('on_message', message)
            return True, accepted_peers
        
        else:
            raise RuntimeError("Message channel is invalid. Note that message channel must be an ID of a group or a person (DM).")
        
        return result
    
    async def create_group(self, group: Group) -> Union[bool, tuple[bool, str]]:
        self._check_authorization()

        if len(group.name) == 0:
            raise RuntimeError("Group's name cannot be empty.")
        
        if len(group.name) > 64:
            raise RuntimeError("Group's name is too large.")
        
        if self.user not in group.members:
            raise RuntimeError("You must be in Group too!")
        
        if len(group.members) < 3:
            raise RuntimeError("Group cannot have less than 2 members.")

        if len(group.members) > 10:
            raise RuntimeError("Group cannot have more than 10 members.")

        accepted_peers = []

        members_without_self = group.members.copy()
        members_without_self.remove(self.user)

        for member in members_without_self:
            result = self.client.send_event(GroupCreated(
                self.client.pdsa,
                base64.b64decode(member.public_key),
                sender=self.client.account,
                recipient=member,
                group=group
            ))
            if isinstance(result, bool) and result == True:
                accepted_peers.append(member)
        
        if len(accepted_peers) == 0:
            raise RuntimeError("All members are offline, hence cannot create the group.")
        
        group.members = accepted_peers
        group.members.append(self.user)
        self.client.add_group(group)
        await self.events.on_group_created(group)

        return True, accepted_peers