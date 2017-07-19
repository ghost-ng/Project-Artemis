#!/usr/bin/python3
import argparse
import re
import socket
import subprocess
import sys
import threading
from time import sleep
import hashlib
global flags, bit

BANNER_ART ="""
    ______      _____       _   
    | ___ \    /  __ \     | |  
    | |_/ /   _| /  \/ __ _| |_ 
    |  __/ | | | |    / _` | __|
    | |  | |_| | \__/\ (_| | |_ 
    \_|   \__, |\____/\__,_|\__|
           __/ |                
          |___/                 

              |\      _,,,,--,,_
              /,`.-'`'    -,  \-;,
             |,4-  ) ),,__ ,\ (  ;;        
            '---''(.'--'  `-'`.)`'  v1.3
            
A python implementation of netcat      
    
    
-h or --help to view the help menu
"""
PASSWORD_OBSCURED = ''
# PASSWORD_CLEAR = "password"
# PASSWORD_OBSCURED = hashlib.sha3_256(PASSWORD_CLEAR.encode()).hexdigest()
# FIRST_MSG = True
#
#
# print(PASSWORD_OBSCURED)

FIRST_MSG = True


def assign_args():
    global flags

    if not len(sys.argv[1:]):

        print(BANNER_ART)

        sys.exit(0)
    else:

        parser = argparse.ArgumentParser(description="Peer to Peer chat client",
                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                         epilog='''Examples:
                Server:   script.py -l 0.0.0.0 -p 9999
                          script.py -l localhost -p 4444 -k [shell]
                Client:   script.py -r 10.0.1.5 -p 4444 -e '/tmp/backdoor.sh'
                          script.py -r 79.86.48.22 -p 4444

                Note:     This is not a TTY terminal and interactive commands like sudo
                          and vi will not work''')
        group = parser.add_mutually_exclusive_group()
        parser.add_argument('-l', '--listen', action='store', dest='listening_addr', const="0.0.0.0",
                            nargs="?", help='Local address to listen on', metavar="[Listening Address]")
        parser.add_argument('-p', '--port', action='store', dest='port', type=int, required=True,
                            metavar="[Target Port]",
                            help='Local port to bind to')
        group.add_argument('-r', '--remote-host', action='store', dest='remote_host', metavar="[Remote Host]",
                            help='Remote IP to connect to')
        group.add_argument('-s', '--shell', action='store_true', dest='shellflg',
                            help='Spawn a shell')
        parser.add_argument('--shell-keyword', action='store', dest='shell_keyword', metavar="[Keyword]",
                            default='exec]',
                            help='The keyword at the beginning of a command to instruct the server to process the'
                                 'following string as a command.  Default is "[exec]"   '
                                 'Example: [exec] ls -al  --> "[exec]" becomes the parameter for this argument and'
                                 'instructs the server to interpret the subsequent strings as shell commands.'
                                 'Note: This is a server side argument')
        parser.add_argument('-e', '--execute', action='store', dest='execute', metavar="[Command to Execute]",
                            help="execute a command; stdout/err is not received on client from any spawned processes")
        parser.add_argument('-u', '--upload', action='store', dest='upload', metavar="[Upload Destination]",
                            help='upload a file; combined with -e it will upload and execute the file')
        parser.add_argument('--upload-keyword', action='store', dest='upload_keyword', metavar="[Keyword]",
                            default='[upload]',
                            help='Change the keyword to instruct the server to upload a file.  Default: "[upload]"')
        parser.add_argument('--run', action='store_true', dest='run',
                            help='Will tell the server side script to execute the uploaded file')
        parser.add_argument('-d', '--debug', action='store_true', dest='debugflg',
                            help='Turn on verbose feedback')
        parser.add_argument('-q', '--quiet', action='store_true', dest='quietflg',
                            help='Supress all error messages; should not be used with -d;'
                                 'verbocity lvls = debug --> no options --> quiet')
        parser.add_argument('-a', '--auth', action='store_true', dest='auth',
                            help='If a client, prompt for the password to authenticate with the server.'
                                 'If a server, prompt for a password to authenticate clients.')
        args = parser.parse_args()


        try:
            len(args.listening_addr)
            listenflg = True
        except:
            listenflg = False
        if args.debugflg:
            debugflg = True
        else:
            debugflg = False
        if args.quietflg:
            quietflg = True
        else:
            debugflg = False
        if args.auth:
            GetPasswd(listenflg)
        if args.execute is not None:
            execflg = True
        else:
            execflg = False
        try:
            len(args.upload)
            uploadflg = True
            upload = args.upload
        except:
            upload = False
        if args.shellflg:
            shellflg = True
        else:
            shellflg = False
        try:
            len(args.exec_cmd)
            exec_cmd = args.exec_cmd
        except:
            exec_cmdflg = False

        flags = {"l": listenflg, "p": args.port, "r": args.remote_host, "u": upload,
                 "upload-keyword": args.upload_keyword, "s": args.shellflg,
                 "e": args.execute, "shell-keyword": args.shell_keyword, "run": args.run, "q": args.quietflg,
                 "d": args.debugflg,"auth":args.auth}

        return args

def GetPasswd(listener):
    global FIRST_MSG
    global PASSWORD_OBSCURED
    if listener:
        print("[?] Password For Client Authentication:")
    PASSWORD_CLEAR = input(">> ")
    PASSWORD_OBSCURED = hashlib.sha3_256(PASSWORD_CLEAR.encode()).hexdigest()

    FIRST_MSG = True

    print("[*] Key:",PASSWORD_OBSCURED)


def main(args):
    version = sys.version_info[0]

    if flags['l'] and not flags['r']:  # Run the server
        run_server = ConnectionThread(args.listening_addr, args.port)
        run_server.start()
        while True:
            try:
                run_server.update()
                if int(version) > 2:
                    response = input("")
                else:
                    response = raw_input("")
            except KeyboardInterrupt:
                if not flags['q']:
                    print("[!] Keyboard Interrupt Detected")
                run_server.terminate_all()
                sys.exit()
            except (ConnectionError, ConnectionAbortedError):
                if not flags['q']:
                    print("[*] Connection Dropped...")
                if not flags['q'] or flags['d']:
                    print("[*] Error:", sys.exc_info())
                sys.exit()
            for c in run_server.clients:
                c[0].send_msg(response + "\n")

    elif flags['r'] and not flags['l']:  # Run the client
        client = Client(args.remote_host, args.port)
        client.start()
        while not flags['e'] and not flags['u']:
            try:
                if int(version) > 2:
                    msg = input("pycat >> ")
                else:
                    msg = raw_input("pycat >> ")
                client.send_msg(msg)
                sleep(.5)
            except KeyboardInterrupt:
                client.tcp_client.close()
                print("\n[*] Keyboard Interrupt Detected!  Quitting...")
                break
            except:
                break
        sys.exit()

    else:  # Handle not -r or -l
        print("[!] You must use either the -r or -l flag and not both together")





class Client(threading.Thread):
    global flags, bit

    def __init__(self, host, port):
        super(Client, self).__init__()
        self.host = host
        self.port = port
        self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data = ""

    def run(self):
        try:
            conn = self.tcp_client.connect((self.host, self.port))
        except (ConnectionError, ConnectionRefusedError):
            if not flags['q']:
                print("[!] Unable to Establish a Connection...")
                print("[*] Check Your Address Arguments -r {h} -p {p}".format(h=self.host, p=self.port))
            sys.exit()
        if flags['d']:
            print('[*] Established a Connection --> {h}:{p}'.format(h=self.host, p=self.port))

        if flags['e']:
            self.send_msg(flags['e'])
            self.recv_msg()
            sys.exit()
        elif flags['u']:
            self.uploadfile(flags['u'])
        else:
            c = ClientServer(self.tcp_client, (self.host, self.port))
            c.start()
            ############################################################################
            # This Function defines the process of sending a file to the target
            # - The file is sent in bytes
            # - The file is appended with an EOF string
            ############################################################################

    def uploadfile(self, filename):

        try:
            file = open(filename, 'rb')

        except FileNotFoundError:
            print("[!] File does not exist")
            sys.exit()
        cmd_str = "{u} <{fn}>".format(u=flags['upload-keyword'], fn=file.name)
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
        if flags['run']:
            self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_client.connect((self.host, self.port))
            if flags['d']:
                print("[*] Attempting to Execute the Uploaded File...")
                print("[*] Listening for Command Output...")
            cmd = " chmod +x ./{file};./{file}".format(file=filename)
            self.send_msg(flags['shell-keyword'] + cmd)
            self.data = ""
            while not self.data.endswith('\n'):
                self.data = self.data + self.tcp_client.recv(1024).decode()
            response = fixmsgformat(self.data)
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
            if flags['d']:
                print("[*] Sent:", msg)

        except (ConnectionResetError, BrokenPipeError):
            if not flags['q']:
                print("[!] Server Terminated Session...")
                raise BrokenPipeError
            if flags['d'] and not flags['q']:
                print("[!] Error:", sys.exc_info())
            sys.exit()
        except:
            if not flags['q']:
                print("[-] Socket Failure!")
                print("[!] Error:", sys.exc_info())

            sys.exit(0)

    def recv_msg(self):
        data = ""
        while True:
            if flags['d']:
                print("[*] Waiting to Receive Data...")
            try:
                if flags['d']:
                    print("[*] Receiving...")
                self.data = self.data + self.tcp_client.recv(1024).decode()
            except:
                if not flags['q']:
                    print("[*] Error -->", sys.exc_info())
                sys.exit()
            response = self.data
            response = fixmsgformat(response)

            print(response)
            if flags['e']:
                break


def fixmsgformat(data):
    while data.endswith('\n'):
        data = data.rstrip('\n')
    return data


class ClientServer(threading.Thread):
    global flags

    def __init__(self, conn, addr):
        super(ClientServer, self).__init__()
        self.conn = conn
        self.addr = addr
        self.data = ''

    def run(self):
        global FIRST_MSG

        # If this is the new connection on the server, then reset the FIRST_MSG to true
        if flags['l']:
            FIRST_MSG = True
        else:
            pass
        upload = False
        while True:

            try:
                if flags['d']:
                    print("[*] Listening for incoming data...")
                while not self.data.endswith('\n'):
                    #self.authenticate()
                    try:
                        self.data = self.data + self.conn.recv(1024).decode()
                        if FIRST_MSG == True and flags['auth'] and flags['l']:
                            if flags['d']:
                                print("Global Vars:")
                                print(globals())
                                print("Local Vars:")
                                print(locals())
                                self.authenticate()

                    except OSError:
                        if flags['d']:
                            print("[!] Error:", sys.exc_info())
                            print("Global Vars:")
                            print(globals())
                            print("Local Vars:")
                            print(locals())
                        sys.exit()
                print(fixmsgformat(self.data))


            except UnicodeDecodeError:
                # Crash quit
                if not flags['q']:
                    print("[*] Session Terminated --> {h}:{p}\n".format(h=self.addr[0], p=self.addr[1]))
                self.conn.close()
                print("Global Vars:")
                print(globals())
                print("Local Vars:")
                print(locals())
                break
            except (ConnectionResetError, ConnectionRefusedError, ConnectionError):
                if not flags['q']:
                    print("[!] Connection Dropped --> {h}:{p}\n".format(h=self.addr[0], p=self.addr[1]))
                break

            if self.data.endswith('\n'):

                if flags['d']:
                    print("[*] Found eol")
                if self.data.startswith('quit'):  # graceful quit
                    if flags['d']:
                        print("[*] Found Termination String!")
                        print("[-] Session terminated --> {h}:{p}\n".format(h=self.addr[0], p=self.addr[1]))

                    self.addr = None
                    self.close()
                    break
                else:
                    if self.data.startswith(flags['shell-keyword']):
                        # run if encounter the execution keyword
                        cmd = self.data.strip(flags['shell-keyword'])
                        if flags['d']:
                            print("[*] Found a shell-keyword:", cmd)

                        response = self.run_command(cmd)
                        self.send_msg(response)

                    elif flags['s']:
                        # run if used as a shell emulator
                        response = self.run_command(self.data)
                        self.send_msg(response)

                    elif self.data.startswith(flags['upload-keyword']):
                        upload = True
                        # run if encouter the upload keyword
                        if flags['d']:
                            print("[*] Attempting to Download a File...")
                        fname_str = self.data.rstrip('\n')
                        fname_str = fname_str.strip(flags['upload-keyword'] + ' ')
                        filename = fname_str.strip("<>")
                        self.downloadfile(filename)  # passes only the filename

                    else:  # This is the normal chat client

                        if not upload and not FIRST_MSG:
                            print(fixmsgformat(self.data))
                    self.data = ''
            else:
                pass

    def authenticate(self):
        global FIRST_MSG
        if PASSWORD_OBSCURED in self.data and flags['l']:
            if flags['d']:
                print("[+] Authenticated! --> {h}:{p}\n".format(h=self.addr[0], p=self.addr[1]))
            self.send_msg(BANNER_ART)
            if flags['d']:
                print("[*] Sent Banner")

                FIRST_MSG = False
            self.data = ""
        elif PASSWORD_OBSCURED not in self.data and flags['l']:
            if flags['d']:
                print("[-] Authentication Failed --> {h}:{p}\n".format(h=self.addr[0], p=self.addr[1]))
            self.conn.close()

    def downloadfile(self, filename):
        # print("Filename -", filename)
        dash = True
        # Remove any file path directories in the name
        while filename.find("/") != -1:
            filename = filename.split("/", 1)[-1]

        file = open('tmp', 'wb')
        if sys.platform == "win32":
            cmd = "move /Y tmp {f} ".format(f=filename)
        else:
            cmd = "mv tmp {f} -f".format(f=filename)
        eof = False
        line = self.conn.recv(1024)
        while line:
            if '<eof>'.encode() in line:
                line = line.rstrip('<eof>'.encode())
                eof = True
            if flags['d']:
                print("[*] EOF Found!")
            file.write(line)
            if not eof:
                line = self.conn.recv(1024)
            else:
                break

        file.close()
        self.run_command(cmd)
        if flags['d']:
            print("[*] Download Complete! Saved --> {f}".format(f=filename))

    def send_msg(self, msg):
        if type(msg) is bytes:
            self.conn.send(msg)
        else:
            try:
                msg = msg + "\n"
                self.conn.send(msg.encode())
            except Exception as e:
                if flags['d']:
                    print(e)
                print(e)
                sys.exit(0)

    def close(self):
        self.addr = None
        self.conn.close()

    # COMMAND EXECUTION FUNCTIONS

    def run_command(self, cmd):
        output = ""
        debug_info = ""
        quiet_info = ""
        cmd_exec_error = ""
        cmd = cmd.rstrip('\n').rstrip('\r')
        if not self.cmd_filter(cmd):  # If it passes the filter; we want the filter to return a False
            try:
                if flags['d']:
                    print("[*] Attempting to Execute Command...")
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode()
                if flags['d']:
                    print("[*] Executed Command:", cmd)
            except subprocess.CalledProcessError as e:
                if not flags['q']:
                    output = "'{c}' --> {e}\n".format(c=cmd, e=e.output)
                    quiet_info = "[!] Command Execution Error! --> "
                    print(quiet_info + output)
                    quiet_info = quiet_info + output
                if flags['d']:
                    print(sys.exc_info())
                    debug_info = str(sys.exc_info())
                response = quiet_info + debug_info
                return response + '\n'

        elif not flags['q']:
            output = "[*] Command Caught: {cmd}\n".format(cmd=cmd)
            print(output)
        return output + '\n'

    def cmd_filter(self, cmd):  # Returns True if the commands contains a forbidden command, else False
        forbidden = ("vi", "vim", "su", "sudo")
        for item in forbidden:
            match = re.findall('\\b' + item + '\\b', cmd) or re.findall(item, cmd)
            if match:
                if not flags['q'] or flags['d']:
                    print("[*] Forbidden Command Found: {cmd}".format(cmd=match))
                return True
        return False


class ConnectionThread(threading.Thread):
    global flags

    def __init__(self, host, port):
        super(ConnectionThread, self).__init__()
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.bind((host, port))
            self.s.listen(5)
            self.host = host
            self.port = port
        except socket.error:
            if not flags['q']:
                print("[!] Failed to create a socket.  Check port bindings!")
            if flags['d']:
                print("[!] Error:", sys.exc_info())
            sys.exit()
        if not flags['q']:
            print("[*] Listening on {h}:{p}".format(h=self.host, p=self.port))
        self.clients = []  # FORMAT: [thread,(socket,(host,port)]

    def __len__(self):
        return len(self.clients)

    def run(self):
        while True:
            conn, address = self.s.accept()

            session = (conn, address)
            c = ClientServer(conn, address)
            c.start()
            if flags['d']:
                print("[*] Client Connected --> {h}:{p}".format(h=address[0], p=address[1]))

            self.clients.append((c, session))
            self.update()



    def send_msg(self, msg, session):
        try:
            if not msg.endswith("\n"):
                msg = msg + "\n"
            session[1][0].send(msg.encode())
        except:
            try:
                self.terminate_all()
            except:
                if flags['d'] and not flags['q']:
                    print("[!] Error:", sys.exc_info())
                sys.exit(0)

    def terminate_all(self):
        for c in self.clients:
            try:
                c[1][0].close()
            except:
                if not flags['q'] and flags['d']:
                    print("[!] Error:", sys.exc_info())
                pass  # Do nothing, program is shutting down
            if flags['d']:
                print("[*] Terminated All Sessions")
            self.clients.remove(c)
        sys.exit()

    def update(self):
        for c in self.clients:
            if c[1][1] is None:
                c[1][0].close()
                self.clients.remove(c)




if __name__ == '__main__':
    args = assign_args()
    main(args)
