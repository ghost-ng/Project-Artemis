import hashlib


def GetPasswd(server):
    """Function to get a password either to use as the authentication token or to pass to a server
    Returns a password str
    :type state: bool"""

    if server is True:
        print("[?] Enter an Authentication Token:")
    if server is False:
        print("[?] Enter the Server's Authentication Token:")
    PASSWORD_CLEAR = input(">> ")
    PASSWORD_OBSCURED = hashlib.sha3_256(PASSWORD_CLEAR.encode()).hexdigest()
    print("[*] Key:",PASSWORD_OBSCURED)
    return PASSWORD_OBSCURED

def Authenticate(passwd,server,data=''):
    """Function to determine if a client provided the correct password
    If this function is called from a client, it will prompt for a password
    If this function is called from a server, it will check for a password in a str object
    Returns True if the correct password was found
    :type data: str"""

    if passwd in data and server is True:
        return True

    elif passwd not in data and server is True:
        return False

