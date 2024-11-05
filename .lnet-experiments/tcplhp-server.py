import socket
import threading

class RendezvousServer:
    def __init__(self,
                    rendezvous_port=9229,

                    encryption_wrapper: 'function' = None,
                    decryption_wrapper: 'function' = None,
                ):
        self.preferred_port = rendezvous_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.peers = {}

        self._encrypt = encryption_wrapper if encryption_wrapper is not None else lambda data: data
        self._decrypt = decryption_wrapper if decryption_wrapper is not None else lambda data: data

        self.public_addr = None
    
    def proceed_peer_thread(self, psock: socket.socket, addr: 'socket._Address'):
        addr = tuple(addr) # Just in case...

        # Receive peer's ID and save it
        peerid = psock.recv(1024)
        self.peers[peerid] = (psock, addr)

        # Send peer's external IP to themselves
        psock.sendall(f'{addr[0]}:{addr[1]}'.encode())

    def start(self):
        self.socket.bind(('0.0.0.0', self.preferred_port))
        self.socket.listen()

        while True:
            try:
                psock, addr = self.socket.accept()
                threading.Thread(target=self.proceed_peer_thread, args=(psock, addr)).start()
            except:
                continue

rzvpeer = RendezvousServer()
rzvpeer.start()