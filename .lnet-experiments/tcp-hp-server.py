import socket
import threading

class RendezvousServer:
    def __init__(self, host='0.0.0.0', port=57790):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))

        self.users = {}

    def rendepeer_thread(self, peersock: socket.socket, addr: tuple):
        peersock.send(b'nn-who.ru?')
        peer_username = peersock.recv(1024).decode()
        self.users[peer_username] = (peersock, addr)
        peersock.send(b'what-you-needhe.re?')

        while True:
            requested_peer = peersock.recv(1024).decode()

            if requested_peer not in self.users:
                peersock.send(b'user not found you dumbass nigger')
                continue
            
            addr1 = str('C:' + self.users[requested_peer][1][0] + ':' + str(self.users[requested_peer][1][1])).encode()
            addr2 = str('S:' + self.users[peer_username][1][0] + ':' + str(self.users[peer_username][1][1])).encode()
            peersock.send(addr1)
            self.users[requested_peer][0].send(addr2)

    def run(self):
        self.socket.listen()
        while True:
            peersock, addr = self.socket.accept()
            threading.Thread(target=self.rendepeer_thread, args=(peersock, addr)).start()

if __name__ == "__main__":
    server = RendezvousServer()
    server.run()