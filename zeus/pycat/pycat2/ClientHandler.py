import socket
import threading
import sys
import Server
import common
import Authlib
from time import sleep

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

        except OSError:
            print("[!] Address is already in use!")
            sys.exit(0)
        except socket.error:
            raise socket.error


        print("[*] Listening on {h}:{p}".format(h=self.host, p=self.port))

    def __len__(self):
        return len(Authlib.clients)

    def run(self):
        while True:
            conn, address = self.s.accept()

            self.c = Server.ClientServer(conn, address)
            self.c.start()
            if common.flags['d']:
                print("[*] Client Connected --> {h}:{p}".format(h=address[0], p=address[1]))
            Authlib.clients.append((conn, False))
            Authlib.update()

    def stop(self):
        try:
            self._is_running = False
            self.c.join()
        except:
            sys.exit(0)

    def terminate_all(self):
        while len(Authlib.clients) > 0:
            self.killclient(0)

    def killclient(self,client_index):
        try:
            Authlib.clients[client_index][0].close()
            peer = str(Authlib.clients[client_index].getpeername()[0]) + ":" + str(Authlib.clients[client_index].getpeername()[1])
            if common.flags['d']:
                print("[+] Killed -->", peer)
            Authlib.update()
#            sleep(10)
        except IndexError:
            print("[-] Client [{}] does not exist!".format(client_index))
            if common.flags['d']:
                print("[!] Debug Error:",sys.exc_info())

        except Exception as e:
            print("[!] Error: Unable to kill client")
            print(sys.exc_info())

        finally:
            Authlib.countclients()

