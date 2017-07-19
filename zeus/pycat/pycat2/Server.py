import threading,common,sys,re,subprocess

class ClientServer(threading.Thread):

    def __init__(self, conn, addr):
        super(ClientServer, self).__init__()
        self.conn = conn
        self.addr = addr
        self.data = ''

    def run(self):

        upload = False
        while True:

            try:
                if common.flags['d']:
                    print("[*] Listening for incoming data...")
                while not self.data.endswith('\n'):
                    #self.authenticate()
                    try:
                        self.data = self.data + self.conn.recv(1024).decode()

                        if self.data.startswith("[chat]"):
                            print(common.fixmsgformat(self.data.split("[chat]")[1]))
                        elif self.data.endswith('\n'):
                            if common.flags['d']:
                                print("[*] Found eol")
                            self.ResolveOptions()

                    except UnicodeDecodeError:
                        # Crash quit
                        if not common.flags['q']:
                            print("[*] Session Terminated --> {h}:{p}\n".format(h=self.addr[0], p=self.addr[1]))
                        self.conn.close()

                        break
                    except (ConnectionResetError, ConnectionRefusedError, ConnectionError):
                        if not common.flags['q']:
                            print("[!] Connection Dropped --> {h}:{p}\n".format(h=self.addr[0], p=self.addr[1]))
                        break
                    except OSError:
                        sys.exit(0)
            except:
                if not common.flags['q']:
                    print("[!] Unknown Error -->", sys.exc_info())



    def ResolveOptions(self):

        if self.data.startswith('quit'):  # graceful quit
            if common.flags['d']:
                print("[*] Found Termination String!")
                print("[-] Session terminated --> {h}:{p}\n".format(h=self.addr[0], p=self.addr[1]))

            self.addr = None
            self.conn.close()
            return
        else:
            if self.data.startswith(common.flags['exec-keyword']):
                # run if encounter the execution keyword
                cmd = self.data.strip(common.flags['exec-keyword'])
                if common.flags['d']:
                    print("[*] Found a shell-keyword:", cmd)

                response = self.run_command(cmd)
                self.send_msg(response)

            elif common.flags['s']:
                # run if used as a shell emulator
                response = self.run_command(self.data)
                self.send_msg(response)

            elif self.data.startswith(common.flags['upload-keyword']):
                upload = True
                # run if encouter the upload keyword
                if common.flags['d']:
                    print("[*] Attempting to Download a File...")
                fname_str = self.data.rstrip('\n')
                fname_str = fname_str.strip(common.flags['upload-keyword'] + ' ')
                filename = fname_str.strip("<>")
                self.downloadfile(filename)  # passes only the filename

            else:  # This is the normal chat client
                print(common.fixmsgformat(self.data))
            self.data = ''


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
            if common.flags['d']:
                print("[*] EOF Found!")
            file.write(line)
            if not eof:
                line = self.conn.recv(1024)
            else:
                break

        file.close()
        self.run_command(cmd)
        if common.flags['d']:
            print("[*] Download Complete! Saved --> {f}".format(f=filename))

    def send_msg(self, msg):
        if type(msg) is bytes:
            self.conn.send(msg)
        else:
            try:
                msg = msg + "\n"
                self.conn.send(msg.encode())
            except Exception as e:
                if common.flags['d']:
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
                if common.flags['d']:
                    print("[*] Attempting to Execute Command...")
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode()
                if common.flags['d']:
                    print("[*] Executed Command:", cmd)
            except subprocess.CalledProcessError as e:
                if not common.flags['q']:
                    output = "'{c}' --> {e}\n".format(c=cmd, e=e.output)
                    quiet_info = "[!] Command Execution Error! --> "
                    print(quiet_info + output)
                    quiet_info = quiet_info + output
                if common.flags['d']:
                    print(sys.exc_info())
                    debug_info = str(sys.exc_info())
                response = quiet_info + debug_info
                return response + '\n'

        elif not common.flags['q']:
            output = "[*] Command Caught: {cmd}\n".format(cmd=cmd)
            print(output)
        return output + '\n'

    def cmd_filter(self, cmd):  # Returns True if the commands contains a forbidden command, else False
        forbidden = ("vi", "vim", "su", "sudo")
        for item in forbidden:
            match = re.findall('\\b' + item + '\\b', cmd) or re.findall(item, cmd)
            if match:
                if not common.flags['q'] or common.flags['d']:
                    print("[*] Forbidden Command Found: {cmd}".format(cmd=match))
                return True
        return False