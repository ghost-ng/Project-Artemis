# import socket

# SERVER_IP = "0.0.0.0"
# SERVER_PORT = 4444

# server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# addr = (SERVER_IP, SERVER_PORT)
# server.bind((SERVER_IP, SERVER_PORT))
# server.listen(100)
# print("Listening on", addr)

# while True:
#     connection, client_address = server.accept()
#     print("Client Connected! -->", client_address)
#     while True:
#         data = input("pycat>> ")
#         connection.send(data.encode())

import sys, socket, select


SOCKET_LIST = []
RECV_BUFFER = 4096
SERVER_IP = '0.0.0.0'
SERVER_PORT = 4444

def master():

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(10)
 
    # add server socket object to the list of readable connections
    SOCKET_LIST.append(server_socket)
 
    print("Listening on", SERVER_PORT)
 
    while True:

        # get the list sockets which are ready to be read through select
        # 4th arg, time_out  = 0 : poll and never block
        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
      
        for sock in ready_to_read:
            # a new connection request recieved
            if sock == server_socket: 
                sockfd, addr = server_socket.accept()
                SOCKET_LIST.append(sockfd)
                print("Connected -->", addr)
                data = input("[{}]".format(addr))
                sockfd.send(data.encode())
            # a message from a client, not a new connection
            else:
                # process data recieved from client, 
                try:
                    # receiving data from the socket.
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        # there is something in the socket
                        pass
                    else:
                        # remove the socket that's broken    
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)

                        # at this stage, no data means probably the connection has been broken
                        #broadcast(server_socket, sock, "Client (%s, %s) is offline\n" % addr) 
                        print("Connection Dropped -->", addr)

                # exception 
                except:
                    #broadcast(server_socket, sock, "Client (%s, %s) is offline\n" % addr)
                    continue

    server_socket.close()

if __name__ == "__main__":
    sys.exit(master())