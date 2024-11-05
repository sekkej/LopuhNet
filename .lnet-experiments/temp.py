import socket
import threading
import time
import json

class HolePunchServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.clients = {}
        
    def handle_client(self, client_sock, addr):
        # Receive client info
        data = client_sock.recv(1024).decode()
        client_info = json.loads(data)
        client_id = client_info['id']
        self.clients[client_id] = {
            'addr': addr,
            'sock': client_sock
        }
        
        # If we have two clients, exchange their information
        if len(self.clients) == 2:
            client_ids = list(self.clients.keys())
            for i in range(2):
                other_id = client_ids[1 - i]
                other_addr = self.clients[other_id]['addr']
                # Send peer information
                peer_info = {
                    'peer_id': other_id,
                    'peer_host': other_addr[0],
                    'peer_port': other_addr[1]
                }
                self.clients[client_ids[i]]['sock'].send(
                    json.dumps(peer_info).encode()
                )
                
    def start(self):
        print(f"Rendezvous server started on {self.host}:{self.port}")
        while True:
            client_sock, addr = self.sock.accept()
            threading.Thread(target=self.handle_client, 
                           args=(client_sock, addr)).start()

class HolePunchClient:
    def __init__(self, client_id, rendezvous_host, rendezvous_port=5000):
        self.client_id = client_id
        self.rendezvous_host = rendezvous_host
        self.rendezvous_port = rendezvous_port
        self.local_port = None
        
    def connect_to_peer(self):
        # Connect to rendezvous server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((self.rendezvous_host, self.rendezvous_port))
        
        # Send our ID to the server
        server_sock.send(json.dumps({
            'id': self.client_id
        }).encode())
        
        # Get peer information from server
        peer_info = json.loads(server_sock.recv(1024).decode())
        peer_host = peer_info['peer_host']
        peer_port = peer_info['peer_port']
        server_sock.close()
        
        # Create socket for peer connection
        peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to same port that was used with rendezvous server
        if self.local_port:
            peer_sock.bind(('0.0.0.0', 9229))
        
        # Try to connect to peer
        try:
            peer_sock.connect((peer_host, peer_port))
            print(f"Connected to peer at {peer_host}:{peer_port}")
            return peer_sock
        except ConnectionRefusedError:
            # If connection fails, listen for incoming connection
            peer_sock.listen(1)
            print("Waiting for peer connection...")
            conn, addr = peer_sock.accept()
            print(f"Peer connected from {addr}")
            return conn

if __name__ == "__main__":
    mode = 'client'
    
    if mode == "server":
        server = HolePunchServer()
        server.start()
    else:
        client_id = '2'
        rendezvous_host = '193.124.115.81'
        client = HolePunchClient(client_id, rendezvous_host)
        sock = client.connect_to_peer()
        
        # Example: send/receive data
        if client_id == "1":
            sock.send(b"Hello from client 1!")
            print(sock.recv(1024).decode())
        else:
            print(sock.recv(1024).decode())
            sock.send(b"Hello from client 2!")