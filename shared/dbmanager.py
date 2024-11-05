import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

import time
import bcrypt
import base64
import xxhash
import sqlite3 as sql

from shared.basic_types import User # type: ignore
from shared.packets import SecurePacket # type: ignore

import logging

class DatabaseException(BaseException):
    """
    Exception during the Database working
    """
    def __init__(self, message, *args: object):
        """
        Exception during the Database working
        """
        super().__init__(message, *args)

class Database:
    def __init__(self, logger: logging.Logger, name='lnet'):
        self.logger = logger

        self.con = sql.connect(f'{name}.db', check_same_thread=False)
        self.cur = self.con.cursor()

        tables = self.cur.execute("SELECT name FROM sqlite_master")
        # If database hasn't been created yet before
        if tables.fetchone() is None:
            self.logger.info("Database hasn't been created yet before, so creating one...")

            self.cur.execute("CREATE TABLE events(time, jPacket, eid)")
            self.cur.execute("CREATE INDEX idx_events_time ON events(time)")

            self.cur.execute("CREATE TABLE users(time, name, username, avatarSeed, publicKey, publicSignKey, uid)")
            self.cur.execute("CREATE INDEX idx_users_time ON users(time)")

            self.con.commit()
        
        self.logger.info("Database initialized!")

    def update_user(self, new_user_data: User):
        # userinfo = self.cur.execute(f"SELECT * FROM users WHERE username='{username}';").fetchone()
        # ip = latest_ip.encode()
        # hashedip = base64.b64decode(userinfo[4])
        # chip = bcrypt.checkpw(ip, hashedip)
        # if not chip:
        #     self.logger.warning(f"User `{username}` changed their IP: {latest_ip} to {current_ip}")
        #     new_ip = base64.b64encode(bcrypt.hashpw(current_ip.encode(), bcrypt.gensalt(10))).decode()
        #     self.cur.execute(f"UPDATE users SET attachedIp='{new_ip}' WHERE username='{username}';")
        #     self.con.commit()
        found_uid = self.cur.execute(f"SELECT * FROM users WHERE uid='{new_user_data.userid}';").fetchone()
        if found_uid is None:
            self.logger.error("User is not found.")
            return False, DatabaseException('User is not found.')
        
        data = new_user_data.__dict__
        columns = ', '.join(data.keys())
        columns = columns \
                    .replace('avatar_seed', 'avatarSeed') \
                    .replace('password_hash', 'phash') \
                    .replace('public_key', 'publicKey') \
                    .replace('userid', 'uid')
        values = ', '.join(['?' for _ in data])
        sql = f"UPDATE users SET ({columns}) = ({values}) WHERE uid='{new_user_data.userid}'"
        self.cur.execute(sql, tuple(data.values()))
        self.con.commit()

        return True

    def fetch_user(self, userid: str = None, username: str = None):
        if userid is None and username is None:
            return None

        if userid is not None:
            fdbuser = self.cur.execute(f"SELECT * FROM users WHERE uid='{userid}';").fetchone()
        else:
            fdbuser = self.cur.execute(f"SELECT * FROM users WHERE username='{username}';").fetchone()
        
        return User.from_db(fdbuser)

    def register(self, user: User, time=time.time()):
        self.logger.info(f"Registering new user: {user.username} (uid: {user.userid})")

        fdbuser = self.cur.execute(f"SELECT * FROM users WHERE username='{user.username}';").fetchone()
        fdbuid = self.cur.execute(f"SELECT * FROM users WHERE uid='{user.userid}';").fetchone()
        if fdbuser is not None or fdbuid is not None:
            self.logger.error("User has been already registered.")
            return False, DatabaseException('User has been already registered.')
        
        if len(user.username) <= 2 or len(user.username) > 36:
            return False, DatabaseException("User's username is too short or too big.")
        if len(user.name) <= 1 or len(user.name) > 48:
            return False, DatabaseException("User's display name is too short or too big.")
        
        if user.avatar_seed < 0:
            return False, DatabaseException("Avatar seed cannot be a negative number.")

        self.cur.execute(f"INSERT INTO users VALUES ({time}, '{user.name}', '{user.username}', {user.avatar_seed}, '{user.public_key}', '{user.public_signkey}', '{user.userid}')")
        self.con.commit()

        self.logger.info("Registration gone successfully!")
        return True
    
    # Deprecated. Replaced with PacketDNA system.
    # def auth(self, username: str, password: str, attached_ip: str):
    #     self.logger.info(f"Authentificating user: `{username}`")

    #     users = self.cur.execute("SELECT * FROM users").fetchall()

    #     if username not in [u[2] for u in users]:
    #         self.logger.warning("User is not found in the Database.")
    #         return False, DatabaseException(f'Username "{username}" not found among registered users.')
        
    #     userinfo = [u for u in users if u[2] == username][0]
    #     password = password.encode()
    #     hashedpwd = base64.b64decode(userinfo[4])
    #     chpw = bcrypt.checkpw(password, hashedpwd)
    #     if not chpw:
    #         self.logger.warning("Given password is invalid for authentificating user.")
    #         return False, DatabaseException(f'Password "{password.decode()}" is invalid.')
        
    #     self.update_ip(username, attached_ip, userinfo[5])
    #     self.logger.info("Authentification gone successfully!")
    #     return True, userinfo
    
    def add_event(self, t: int, secure_packet: bytes, eid: str = None):
        # if len(recv_keys) == 0:
        #     return False, DatabaseException('List of keys for recipients cannot have length of 0.')
        
        # Deprecated
        # # If UTC times are different by 5 minutes
        # if abs(time.time_ns() - t) >= 300000000000:
        #     return False, DatabaseException('Can\'t add event that was sent more than 5 minutes ago, it\'s too outdated and might be a security-breaking.')

        b64packet = base64.b64encode(secure_packet).decode()
        # b64recv_keys = [base64.b64encode(k).decode() for k in recv_keys]
        # json_recvkeys = json.dumps(b64recv_keys)

        if eid is None:
            eid = xxhash.xxh128(f'{time.time_ns()}').hexdigest()
        else:
            packet_exists = self.cur.execute(f"SELECT * FROM events WHERE eid='{eid}';").fetchone()
            if packet_exists is not None:
                raise DatabaseException(f'Event with id {eid} have already been registered in Database.')

        self.cur.execute(f"INSERT INTO events VALUES ({t}, '{b64packet}', '{eid}')")
        self.con.commit()

        self.logger.debug('Added new event.')
        return True
    
    def add_events(self, event_list: list[tuple[int, bytes, str|None]]):
        added_events = 0

        for t, secure_packet, eid in event_list:
            b64packet = base64.b64encode(secure_packet).decode()

            if eid is None:
                eid = xxhash.xxh128(f'{time.time_ns()}').hexdigest()
            else:
                packet_exists = self.cur.execute(f"SELECT * FROM events WHERE eid='{eid}';").fetchone()
                if packet_exists is not None:
                    continue # Event with that id have already been registered in Database.

            added_events += 1
            self.cur.execute(f"INSERT INTO events VALUES ({t}, '{b64packet}', '{eid}')")
        
        self.con.commit()
        self.logger.debug(f'Added {added_events}/{len(event_list)} events.')
        return True
    
    def remove_event(self, index: int):
        self.cur.execute(f"DELETE FROM table_name WHERE rowid = {index+1};")
        self.con.commit()

        self.logger.debug(f'Removed event at index: {index}.')
        return True
    
    def get_checksum(self):
        self.cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = self.cur.fetchall()

        dbvalue = b''
        for table in tables:
            table_name = table[0]
            
            # Get all rows from the table
            self.cur.execute(f"SELECT * FROM {table_name}")
            rows = self.cur.fetchall()

            # Update the hash with table name and row data
            dbvalue += table_name.encode('utf-8')
            for row in rows:
                dbvalue += str(row).encode('utf-8')
        
        return xxhash.xxh128(dbvalue).hexdigest()

# import logging
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
#     datefmt='%Y-%m-%d %H:%M:%S.%MS',
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

# # DB Creation
# db = Database(logger, 'dev')

# # Registration
# p = '$lemonhead3310S*'.encode()
# password = base64.b64encode(
#                 bcrypt.hashpw(p, bcrypt.gensalt(16))
#             ).decode()
# ip = base64.b64encode(bcrypt.hashpw(b'192.168.0.1', bcrypt.gensalt(10))).decode()
# print(db.register(User('lnet uid 1', 'sekkej', 1488, password, ip)))
# print(db.register(User('lnet uid 2', 'peterpavel', 1337, password, ip)))

# # Update user
# db.update_user(User('lnet uid 1', 'sekkej', 1223, "JDJiJDE2JHROdmI2Nm50Nm5NdVlCbkVoM0ZnZHVJbm9xN0VzN0loOWVZNU9KQ29ZWk80Ni9yZWc4N20u", "JDJiJDEwJGZyaDFZQlI3ZUptb2wxTk5oV3M4bnUwRnoxT0tlRnhIYzdMNE5ubFcuNjFMcURYcGxVUmsu", 'ab163eb9d8b55a79b1e03ccaa7028c06'))

# # Basic event creation
# from shared.packets import MsgCreated # type: ignore
# from shared.basic_types import Message # type: ignore

# # Private shared key between user1 and user2
# shared_key = b'A shared key, that length is: 32'

# p = MsgCreated(
#     shared_key,
#     user1,
#     [user2],
#     Message(
#         user1,
#         'DM1',
#         'Hello, user2! Me — user1, waving to you.',
#         time.time_ns()
#     )
# )

# enc = bytes(p)
# print(enc)
# recre = MsgCreated.from_bytes(p.iv, shared_key, enc)
# print(recre._json)

# print(db.add_event(time.time_ns()-10000000, [b'oirgeilurgieulrghlejikrfg', b'arghkaejrgkjerhlkueahl'], bytes(p)))





# # # Deprecated:
# # Authorization
# user1 = db.auth('sekkej', '$lemonhead3310S*', '1.4.8.8')[1]
# print(user1)
# user2 = db.auth('peterpavel', '$lemonhead3310S*', '192.168.0.1')[1]
# # print(user2)
# 
# # #
# # # Packet creation
# # # keygen
# # key = os.urandom(32)
# # pckt = SecurePacket(
# #     key,
# #     User.from_db(user1),
# #     ('DM1', [User.from_db(user2)]),
# #     {
# #         'msg': '🤣msgCreate☺',
# #         'i': 1,
# #         'b': True
# #     }
# # )
# 
# # # Standard-LNET-Packet Serialization
# # serialization   = bytes(pckt)
# # print("Serialized:")
# # print(serialization)
# # deserialization = SecurePacket.from_bytes(pckt.iv, key, serialization)
# 
# # # Standard-LNET-Packet Deserialization
# # print("\nDeserialized:")
# # print(deserialization.sender)
# # print(deserialization.recipient)
# # print(deserialization.data)