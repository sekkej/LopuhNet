import socket

def send_message(s, ip, port, message):
    try:
        # UDP
        s.sendto(message.encode('utf-8'), (ip, port))
    except Exception as e:
        print("An error occurred:", e)

if __name__ == '__main__':
    target_ip = '212.46.10.56'
    target_port = 57700

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_message(s, target_ip, target_port, input(' >> '))