import sys
import socket
import select

SERVER_PORT = 4444
SERVER_IP = '10.0.0.5'

def slave():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
     
    # connect to remote host
    try :
        s.connect((SERVER_IP, SERVER_PORT))
    except :
        print("Unable to connect")
        sys.exit()
     
    print("Connected!")
     
    while True:
        socket_list = [s]
         
        # Get the list sockets which are readable
        ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])
         
        for sock in ready_to_read:             
            if sock == s:
                # incoming message from remote server, s
                data = sock.recv(1024)
                if not data :
                    print('\nDisconnected from chat server')
                    sys.exit()
                else :
                    #print data
                    print(data.decode())  

if __name__ == "__main__":
    sys.exit(slave())