import hashlib
import common
from sys import exc_info

clients = []                #FORMAT: [(socket_conn,(host,port))]  --> [(conn, address)]
auth_conns = []             #FORMAT: [(socket_conn,(host,port))]  --> [(conn, address)]

client_auth_token = ""    #The token used to prove authentication
server_auth_token = ""



def update(conn_list):
    global clients
    global auth_conns
    if conn_list == clients:
        conn_type = "Connected"
    else:
        conn_type = "Authenticated"
    if common.flags['d']:
        print("[*] Debug Info:")
        print(conn_type,conn_list)
    count = 0

    if len(conn_list) == 1 and "closed" in str(conn_list):
        clients = []
        count = 1
    elif len(conn_list) > 1:
        for c in conn_list:
            if "closed" in str(c):
                try:
                    conn_list.remove(c)
                    count =+1
                except ValueError:
                    pass
                if common.flags['d']:
                    print("[*] Removed Client from {} List:".format(conn_type),c)
    print("[*] Removed {} Clients".format(count))


    # if len(auth_conns) == 1:
    #     auth_conns = []
    #     count = 1
    # elif len(auth_conns) > 1:
    #     for c in auth_conns:
    #         if "closed" in str(c):
    #             try:
    #                 auth_conns.remove(c)
    #                 count += 1
    #             except ValueError:
    #                 pass
    #             if common.flags['d']:
    #                 print("[*] Removed client from authenticated clients list:",c)


def findIndexofClient(conn):
    try:
        index = auth_conns.index(conn)
        print("[*] Found Index:",index)
        return index
    except:
        print("[!] Unable to find client index in Authenticated Client List")
        if common.flags['d']:
            print(exc_info())


def listclients():
    global clients
    global auth_conns

    update(auth_conns)
    update(clients
           )
    loop = 0
    list_type = "Connected"
    li = clients

    while loop < 1:

        if len(li) == 0:
            print("[*] There are no {} clients".format(list_type))
        else:
            print("[*] {} List:".format(list_type))
            num = 0
            for c in li:
                print(str(li.index(c)) + ") " + str(c[1]))
                num += 1
        loop = + 1
        if common.flags['d']:
            print("[*] Raw List:")
            print(li)
        li = auth_conns
        list_type = "Authenticated"


def countclients():

    total = len(clients)
    print("[*] Total Clients:", total)

def PromptPasswd():
    global server_auth_token
    global client_auth_token

    """Function to get a password either to use as the authentication token or to pass to a server
    Returns a password str
    :type state: bool"""

    if common.flags['key'] and common.flags['l']:
        server_auth_token = common.flags['key']
        return
    elif common.flags['key'] and common.flags['r']:
        client_auth_token = common.flags['key']
        return

    try:
        passwd_plaintext = input("[?] Enter a Passphrase: ")
    except KeyboardInterrupt:
        raise KeyboardInterrupt

    passwd_encoded = hashlib.sha3_256(passwd_plaintext.encode()).hexdigest()
    print("[*] Key:",passwd_encoded)
    if common.flags['l']:
        server_auth_token = passwd_encoded
    if common.flags['r']:
        try:
            token = input("[?] Enter the Authentication Token: ")
        except KeyboardInterrupt:
            raise KeyboardInterrupt

        client_auth_token = token


def CheckPasswd(token=server_auth_token,data=''):
    """Function to determine if a client provided the correct password
    If this function is called from a client, it will prompt for a password
    If this function is called from a server, it will check for a password in a str object
    Returns True if the correct password was found
    :type data: str"""

    if token in data:
        return True

    elif token not in data:
        return False

def AuthenticateClient():
    PromptPasswd()
    return client_auth_token

def AuthenticateServer(conn=None,addr=None,data=""):
    global auth_conns

    if common.flags['auth'] or common.flags['key']:
        try:
            auth_conns.index(conn)
            authenticated = True
            if common.flags['d']:
                print("[*] Client is already authenticated")
        except ValueError:
            authenticated = False

        if not authenticated:
            token = common.fixmsgformat(data.strip("[auth]"))
            auth = CheckPasswd(server_auth_token, token)
            if auth == False:
                if common.flags['d']:
                    print("[*] Authentication failed")
                return False
            else:
                auth_conns.append(conn,addr)
                if common.flags['d']:
                    print("[*] Client is now authenticated -->",str(conn.getpeername()[0])+":"+str(conn.getpeername()[1]))
                return True