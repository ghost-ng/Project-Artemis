import socket
import threading
import sys, os

LISTENING_IP = "0.0.0.0"
SERVER_PORT = 4444
SERVER_IP = "10.0.0.5" 

CLIENT = ""
SERVER = ""
CLIENT_LIST = []

#############################################
#   This function checks if a file exists   #
#   on the server                           #
#############################################

def file_exists(filename):
    exists = os.path.isfile(filename)  # initial check 
    try:
        if filename is not None:
            while exists is False:
                print_fail("File does not exist, try again")
                file = input("[New File]>> ")
                return file_exists(file)
    except KeyboardInterrupt:
        return None
    return filename


#############################################
#   This class allows the client to listen  #
#   to the server                           #
#############################################

class ClientServer(threading.Thread):
    def __init__(self, conn, addr):
        super(ClientServer, self).__init__()
        self.conn = conn
        self.addr = addr
        self.data = ''

    def run(self):
        while True:
            try:
                data = input(">>").lower()
                cmds = data.split()
                if cmds[0] == "send":       # send cmd.exe cmd.exe   [cmd] [file to send] [save-as]
                    filename = file_exists(cmds[1])
                    if filename is not None:
                        self.conn.send(data.encode())
                        print("Sending File...")
                        with open(filename,'rb') as file:
                            stream = file.read(1024)
                            self.conn.send(stream)
                        print("Sent!")
                else:
                    self.conn.send(data.encode())
                if data.lower() == "exit":
                    self.conn.close()
            except KeyError:
                pass    
            except:
                self.conn.close()
                break


######################################################################
#   This class handles the inbound connections to the server.        #
#    It will migrate new connections to their own thread, allowing   #
#    for multiple inbound connections                                #
######################################################################

class ServerConnectionThread(threading.Thread):
 
    def __init__(self, host, port):
        super(ServerConnectionThread, self).__init__()
        self.port = port
        self.host = host
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((host, port))
        self.s.listen(5)
        print("[*] Listening on {h}:{p}".format(h=self.host, p=self.port))
        self.host = host
        self.port = port
        self.data = ""

    def run(self):
        while True:
            client_conn = self.s.accept()
            print(client_conn)
            conn, address = client_conn
            print("Received Connection-->", address)
            client_conn = ClientServer(conn, address)
            client_conn.start()
            CLIENT_LIST.append(conn)
            while not self.data.endswith('\n'):
                try:
                    self.data = self.data + conn.recv(1024).decode()
                except ConnectionAbortedError:
                    pass
            print(self.data)

    def stop(self):
        self._is_running = False
        for conn in CLIENT_LIST:
            conn.join()
        sys.exit(0)
#############################################
#   This class is for a client to connect   #
#   back to the server,                       #
#############################################

class Client(threading.Thread):

    def __init__(self, host, port):
        super(Client, self).__init__()
        self.host = host
        self.port = port
        print("Connecting to:", host, port)
        self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        

    def run(self):
#This function's sole purpose is to phone home and receive instructions
        try:
            self.tcp_client.connect((self.host, self.port))
            print("Connected!")
        except:
            pass
        while True:
            try:
                self.data = self.tcp_client.recv(1024).decode()
                if self.data == "exit":
                    self.tcp_client.close()
                    sys.exit(0)
                elif "send" in self.data.split():
                    print("Received File Upload Command!")
                    print(self.data.split())
                    self.download_file(self.data.rstrip().split())
                else:
                    print(self.data)
            except IndexError:
                pass
            except Exception as e:    
                print(sys.exc_info())
                print(e)
                break
    
    def download_file(self, cmds):
        print("Downloading...")
        data = ""
        if len(cmds) >= 2 and cmds[0] == "send":
            save_filename = cmds[1]
            try:
                save_filename = cmds[2]
                print("New Name:", save_filename)
            except IndexError:
                pass
            with open(save_filename, 'wb') as file:
                while data != bytes(''.encode()):
                    data = self.tcp_client.recv(1024)
                    file.write(data)
            file.close()
            print("File Transfered!")

if __name__ == "__main__":
    if SERVER is True or sys.argv[1].lower() == "server":
        run_server = ServerConnectionThread(LISTENING_IP, SERVER_PORT)
        run_server.start()

    elif CLIENT is True or sys.argv[1].lower() == "client":
        tcp_client = Client(SERVER_IP, SERVER_PORT)
        tcp_client.start()