from printlib import *
from os import kill, getpid
from signal import SIGTERM

def configure(conn):
    query(conn)
    ans = print_question_list("Set up a Beacon Task", "1 - Current Session", "2 - Future Tasking")
    if ans == "1":
        try:
            int(ans)
            send_data(conn, "[BEACON]{}".format(ans))
        except:
            print("Error: No change")
    elif ans == "2":
        

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