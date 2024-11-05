import socket
import threading

class RendezvousPeer:
    def __init__(self,
                    rendezvous_host='127.0.0.1',
                    rendezvous_port=9229,

                    encryption_wrapper: 'function' = None,
                    decryption_wrapper: 'function' = None,
                ):
        self.server_addr = (rendezvous_host, rendezvous_port)
        self.rendezvous_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.rendezvous_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.peers = {}

        self._encrypt = encryption_wrapper if encryption_wrapper is not None else lambda data: data
        self._decrypt = decryption_wrapper if decryption_wrapper is not None else lambda data: data

        self.public_addr = None
    
    def connect_to(self, peer_id: str):
        if peer_id in self.peers:
            return self.peers[peer_id]
        
        self.rendezvous_socket.sendall()
    
    def start(self, own_id: str):
        # Connect to the Rendezvous server
        self.rendezvous_socket.connect(self.server_addr)
        # Send self ID (peer_id)
        self.rendezvous_socket.sendall(self._encrypt(own_id.encode()))

        # Save our public (external) IP
        received_external_ip = self._decrypt(self.rendezvous_socket.recv(1024)).decode().split(':')
        received_external_ip[1] = int(received_external_ip[1]) # Port must be an integer
        received_external_ip = tuple(received_external_ip) # List to address (tuple)
        self.public_addr = received_external_ip

# Usage for Sekkej
rzvpeer = RendezvousPeer('193.124.115.81')
rzvpeer.start('sekkej')
input()