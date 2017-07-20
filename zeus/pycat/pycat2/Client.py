import sys,threading,socket,common
import ClientHandler,Server
from time import sleep


class Client(threading.Thread):


    def __init__(self, host, port):
        super(Client, self).__init__()
        self.host = host
        self.port = port
        self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data = ""
        self.c = ""

    def run(self):
        try:
            conn = self.tcp_client.connect((self.host, self.port))
        except (ConnectionError, ConnectionRefusedError):
            if not common.flags['q']:
                print("[!] Unable to Establish a Connection...")
                print("[*] Check Your Address Arguments -r {h} -p {p}".format(h=self.host, p=self.port))
            raise (ConnectionError, ConnectionRefusedError)
        if common.flags['d']:
            print('[*] Established a Connection --> {h}:{p}'.format(h=self.host, p=self.port))

        if common.flags['e']:
            self.send_msg(common.flags['e'])
            self.recv_msg()
            sys.exit()
        elif common.flags['u']:
            self.uploadfile(common.flags['u'])
        else:
            self.c = Server.ClientServer(self.tcp_client, (self.host, self.port))
            self.c.daemon = True
            self.c.start()
            ############################################################################
            # This Function defines the process of sending a file to the target
            # - The file is sent in bytes
            # - The file is appended with an EOF string
            ############################################################################

    def stop(self):
        try:
            self._is_running = False
            self.c.join()
        except:
            sys.exit(0)

    def uploadfile(self, filename):

        try:
            file = open(filename, 'rb')

        except FileNotFoundError:
            print("[!] File does not exist")
            sys.exit()
        cmd_str = "{u} <{fn}>".format(u=common.flags['upload-keyword'], fn=file.name)
        self.send_msg(cmd_str)
        sleep(1)
        print("[*] Uploading...")
        sleep(.5)
        line = file.read(1024)
        while line:
            try:
                self.tcp_client.send(line)
                line = file.read(1024)
            except:
                print("[-] Socket Failure!")
        self.tcp_client.send("<eof>".encode())  # signifies the end of the file
        file.close()
        print("[*] Upload Complete!")
        self.tcp_client.close()
        sleep(1)
        if common.flags['run']:
            self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_client.connect((self.host, self.port))
            if common.flags['d']:
                print("[*] Attempting to Execute the Uploaded File...")
                print("[*] Listening for Command Output...")
            cmd = " chmod +x ./{file};./{file}".format(file=filename)
            self.send_msg(common.flags['shell-keyword'] + cmd)
            self.data = ""
            while not self.data.endswith('\n'):
                self.data = self.data + self.tcp_client.recv(1024).decode()
            response = common.fixmsgformat(self.data)
            sleep(.5)
            print(response)
            self.tcp_client.close()
            sys.exit()

    def send_msg(self, msg):

        mod = msg
        while mod.endswith('\n'):
            mod = mod.rstrip('\n')
        msg = mod + '\n'
        try:
            if type(msg) is bytes:
                request = msg
            else:
                request = msg.encode()
            self.tcp_client.send(request)
            if common.flags['d']:
                print("[*] Sent:", msg)

        except (ConnectionResetError, BrokenPipeError):
            if not common.flags['q']:
                print("[!] Server Terminated Session...")

            if common.flags['d']:
                print("[!] Error:", sys.exc_info())
            raise Exception

        except:
            if not common.flags['q']:
                print("[-] Socket Failure!")
                print("[!] Error:", sys.exc_info())

            raise Exception

    def recv_msg(self):
        data = ""
        while True:
            if common.flags['d']:
                print("[*] Waiting to Receive Data...")
            try:
                if common.flags['d']:
                    print("[*] Receiving...")
                self.data = self.data + self.tcp_client.recv(1024).decode()
            except:
                if not common.flags['q']:
                    print("[*] Error -->", sys.exc_info())
                raise Exception
            response = self.data
            response = common.fixmsgformat(response)

            print(response)
            if common.flags['e']:
                break
