import hashlib
import common

clients = []                #FORMAT: [(socket_conn,(host,port))]
auth_conns = []             #FORMAT: [conn]

client_auth_token = ""    #The token used to prove authentication
server_auth_token = ""



def update():
    global clients

    for c in clients:
        if "closed" in str(c):
            clients.remove(c)
            if common.flags['d']:
                print("[*] Removed client from connected clients list")
            try:
                auth_conns.remove(c[0])
            except ValueError:
                pass
            if common.flags['d']:
                print("[*] Removed client from authenticated clients list")

def listclients():
    global clients

    update()
    if len(clients) == 0:
        print("[*] There are no connected clients")
    else:
        print("[*] Client List:")
        num = 0
        for c in clients:
            print(str(clients.index(c)) + ") " + str(c[1]))
            num += 1

def listauthenticated():
    if len(auth_conns) == 0:
        print("[*] There are no authenticated clients")
    else:
        print("[*] Authenticated Client List:")
        num = 0
        for c in auth_conns:
            print(chr(ord('a') + num) + ") " + str(c.getpeername()))
            num += 1

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

def AuthenticateServer(conn=None,data=""):
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
                auth_conns.append(conn)
                if common.flags['d']:
                    print("[*] Client is now authenticated -->",str(conn.getpeername()[0])+":"+str(conn.getpeername()[1]))
                return True