import socket
import threading
import sys
import Server
import common

class ConnectionThread(threading.Thread):
    """This class handles the inbound connections to the server.
    It will migrate new connections to their own thread, allowing
    for multiple inbound connections"""


    def __init__(self, host, port):
        super(ConnectionThread, self).__init__()
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.bind((host, port))
            self.s.listen(5)
            self.host = host
            self.port = port

        except socket.error:
            raise socket.error

        print("[*] Listening on {h}:{p}".format(h=self.host, p=self.port))
        self.clients = []  # FORMAT: [thread,(socket,(host,port)]

    def __len__(self):
        return len(self.clients)

    def run(self):
        while True:
            conn, address = self.s.accept()

            c = Server.ClientServer(conn, address)
            c.start()
            if common.flags['d']:
                print("[*] Client Connected --> {h}:{p}".format(h=address[0], p=address[1]))

            self.clients.append((c, (conn, address)))
            self.update()

    def terminate_all(self):
        for c in self.clients:
            try:
                c[1][0].close()
                self.clients.remove(c)
            except:
                if not common.flags['q']:
                    print("[!] Error:", sys.exc_info())
                raise Exception

        if common.flags['d']:
            print("[*] Terminated All Sessions")

        sys.exit(0)

    def update(self):
        for c in self.clients:
            if c[1][1] is None:
                c[1][0].close()
                self.clients.remove(c)

    def listclients(self):
        if len(self.clients) == 0:
            print("[*] There are no connected clients")
        else:
            print("[*] Client List:")
            num = 0
            for c in self.clients:
                print(str(num) + ". " + str(c[1][1]))
                num += 1

    def countclients(self):
        total = len(self.clients)
        print("[*] Total Clients:",total)


    def killclient(self,index):
        num = 0
        for c in self.clients:
            if num == index:
                c[1][0].close()
                self.clients.remove(num)
                print("[-] Killed -->", self.clients[index][1][1])
                return
            num += 1
        print("[!] Client does not exist!")