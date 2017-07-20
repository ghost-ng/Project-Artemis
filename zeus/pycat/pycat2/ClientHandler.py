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
            self.c = ""

        except socket.error:
            raise socket.error

        print("[*] Listening on {h}:{p}".format(h=self.host, p=self.port))
        self.clients = []  # FORMAT: [thread,(socket,(host,port)]

    def __len__(self):
        return len(self.clients)

    def run(self):
        while True:
            conn, address = self.s.accept()

            self.c = Server.ClientServer(conn, address)
            self.c.start()
            if common.flags['d']:
                print("[*] Client Connected --> {h}:{p}".format(h=address[0], p=address[1]))

            self.clients.append((self.c, (conn, address)))
            self.update()
    def stop(self):
        try:
            self._is_running = False
            self.c.join()
        except:
            sys.exit(0)
    def terminate_all(self):
        if len(self.clients) > 0:
            for sock in self.clients:
                self.killclient(self.clients.index(sock))
        else:
            self.terminate_all()


    def update(self):
        for c in self.clients:
            if "closed" in str(c):
                self.clients.remove(c)

    def listclients(self):
        if len(self.clients) == 0:
            print("[*] There are no connected clients")
        else:
            print("[*] Client List:")
            num = 0
            for c in self.clients:
                print(str(self.clients.index(c)) + ") " + str(c[1][1]))
                num += 1

    def countclients(self):
        total = len(self.clients)
        print("[*] Total Clients:",total)


    def killclient(self,client_index):
        try:

            self.clients[client_index][0].close()
            print("[-] Killed -->", str(self.clients[client_index][1][1][0]) + ":" + str(self.clients[client_index][1][1][1]))
            self.update()
        except IndexError:
            print("[!] Client [{}] does not exist!".format(client_index))
            if common.flags['d']:
                print(sys.exc_info())

        except:
            print("[!] Error: Unable to kill client")
            print(sys.exc_info())

        finally:
            self.countclients()

