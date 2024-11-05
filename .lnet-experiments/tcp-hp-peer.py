# import socket
# import threading

# class RendezvousPeer:
#     def __init__(self, rendezvous_host='127.0.0.1', rendezvous_port=57790, port=57790):
#         self.preferred_port = port
#         self.server_addr = (rendezvous_host, rendezvous_port)
#         self.rendezvous_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.rendezvous_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         self.peer_socket = None

#     def _run(self, username):
#         self.rendezvous_socket.connect(self.server_addr)
#         self.rendezvous_socket.recv(1024)
#         self.rendezvous_socket.send(username.encode())
#         self.rendezvous_socket.recv(1024)
#         self.listen_messages(self.rendezvous_socket)
    
#     def listen_messages(self, sock: socket.socket):
#         while True:
#             if 'closed' in repr(sock):
#                 continue
#             self.on_netmessage(sock.recv(1024))

#     def on_netmessage(self, data: bytes):
#         if data.startswith(b'C:') or data.startswith(b'S:'):
#             address = data.decode().split(':')
#             address[2] = int(address[2])
#             is_serving = address[0] == 'S'
#             address.pop(0)
#             address = (address[0], 57792)

#             self.rendezvous_socket.close()
#             print(f'Connecting to peer: {address}...')
            
#             self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             self.peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#             # self.peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

#             if is_serving:
#                 print('Serving...')
#                 self.peer_socket.bind(('0.0.0.0', self.preferred_port))
#                 self.peer_socket.listen(1)
#                 self.peer_socket, _ = self.peer_socket.accept()
#                 print('Accepted connection!')
#             else:
#                 try:
#                     self.peer_socket.connect(address)
#                     print('Connected!')
#                 except Exception as e:
#                     print(f"Connection failed: {e}")
#                     return
            
#             threading.Thread(target=self.listen_messages, args=(self.peer_socket,)).start()
#         else:
#             print('recv', data)

#     def start(self, username: str):
#         threading.Thread(target=self._run, args=(username,)).start()
    
#     def holepunch_to(self, username: str):
#         self.rendezvous_socket.send(username.encode())

#     def send(self, message: str):
#         if self.peer_socket:
#             self.peer_socket.send(message.encode())
#         else:
#             print("No peer connection established")

# # Usage for first peer (Sekkej):
# peer = RendezvousPeer('193.124.115.81', 57790, 57791)
# peer.start('sekkej')
# peer.holepunch_to(input("Enter peer username to connect to: "))

# while True:
#     message = input('>> ')
#     peer.send(message)

# # Usage for second peer (Vasily):
# # peer = RendezvousPeer('193.124.115.81', 57790, 57792)
# # peer.start('vasily')

# # while True:
# #     message = input('>> ')
# #     peer.send(message)

import sys
import logging
import socket
from threading import Event, Thread
from util import *

logger = logging.getLogger('client')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
STOP = Event()

def __listen_p2p_messages(peer_sock):
    while True:
        try:
            print(peer_sock.recv(1024))
        except ConnectionResetError:
            break

def start_p2p_chatting(peer_sock):
    Thread(target=__listen_p2p_messages, args=(peer_sock,)).start()
    while True:
        try:
            peer_sock.send(input('>> ').encode())
        except:
            continue

def accept(port):
    logger.info("accept %s", port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', port))
    s.listen(1)
    s.settimeout(5)
    while not STOP.is_set():
        try:
            conn, addr = s.accept()
            Thread(target=start_p2p_chatting, args=(conn,)).start()
        except socket.timeout:
            continue
        else:
            logger.info("Accept %s connected!", port)
            # STOP.set()

def connect(local_addr, addr):
    logger.info("connect from %s to %s", local_addr, addr)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(local_addr)
    while not STOP.is_set():
        try:
            s.connect(addr)
            Thread(target=start_p2p_chatting, args=(s,)).start()
        except socket.error:
            continue
        else:
            logger.info("connected from %s to %s success!", local_addr, addr)


def main(host='193.124.115.81', port=5005):
    sa = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sa.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sa.connect((host, port))
    priv_addr = sa.getsockname()

    send_msg(sa, addr_to_msg(priv_addr))
    data = recv_msg(sa)
    logger.info("client %s %s - received data: %s", priv_addr[0], priv_addr[1], data)
    pub_addr = msg_to_addr(data)
    send_msg(sa, addr_to_msg(pub_addr))

    data = recv_msg(sa)
    pubdata, privdata = data.split(b'|')
    client_pub_addr = msg_to_addr(pubdata)
    client_priv_addr = msg_to_addr(privdata)
    logger.info(
        "client public is %s and private is %s, peer public is %s private is %s",
        pub_addr, priv_addr, client_pub_addr, client_priv_addr,
    )

    threads = {
        '0_accept': Thread(target=accept, args=(priv_addr[1],)),
        '1_accept': Thread(target=accept, args=(client_pub_addr[1],)),
        '2_connect': Thread(target=connect, args=(priv_addr, client_pub_addr,)),
        '3_connect': Thread(target=connect, args=(priv_addr, client_priv_addr,)),
    }
    for name in sorted(threads.keys()):
        logger.info('start thread %s', name)
        threads[name].start()

    while threads:
        keys = list(threads.keys())
        for name in keys:
            try:
                threads[name].join(1)
            except TimeoutError:
                continue
            if not threads[name].is_alive():
                threads.pop(name)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, message='%(asctime)s %(message)s')
    main()