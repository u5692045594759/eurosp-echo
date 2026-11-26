import socket
import threading

#######################################################
#                                                     #
#   Simple echo server                                #
#   python(3) echo.py                                 #
#                                                     #
#######################################################

TIMEOUT = 10 # seconds
PORT = 7


def handle(client_socket):
    with client_socket:
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    return
                client_socket.sendall(data)
            except OSError:
                return

# creating server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", PORT))
server.listen()

while True: # listen for incoming connections
    client_socket, address = server.accept()
    client_socket.settimeout(TIMEOUT)
    print("request from the ip", address[0])
    # spawn a new thread that run the function handle()
    threading.Thread(target=handle, args=(client_socket, )).start()
