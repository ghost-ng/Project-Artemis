import Authlib,common
from sys import exc_info
help_menu = [
"""show clients connected
    --> List all connected clients
""",
"""show clients authenticated
    --> List only authenticated clients
""",
"""count clients
    --> Show the total # of connected clients
""",
"""update
    --> Refresh the client list
""",
"""kill all
    --> Terminate all the connected clients
""",
"""kill [id]
    --> Terminate a select client.  ID is found with 'show clients'.
""",
"""chat [id] [message]
    --> Send a message to a specific client.  ID is found with 'show clients'.
""",
"""chat all
    --> Send a message to all connected clients
""",
"""exec all [command]
    --> Send a command to all connected clients.
""",
"""exec [id] [command]
    --> Send a command to a specific client.  ID is found with 'show clients'.
""",
"""help
    --> View the help menu
""",
"""help [keyword]
    --> Display specific help topics
"""
]

def resolveOpts(msg,server):
    if msg == "help":
        if common.flags['d']:
            print("[*] Menu --> Help")
        print("")
        print("Help Menu:")
        for item in help_menu:
            print(item)
    elif "help " in msg:
        for item in help_menu:
            if msg.split(" ")[1] in item:
                print(item)
    elif msg == "update":
        if common.flags['d']:
            print("[*] Menu --> Update")
        Authlib.update()
        Authlib.listclients()
        Authlib.listauthenticated()

    elif msg == "show clients":
        if common.flags['d']:
            print("[*] Menu --> Show Clients")
        Authlib.listclients()
        Authlib.listauthenticated()
    elif msg.startswith("show clients"):        #Options show clients [connected,authenticated]
        Authlib.listclients()
    elif msg.startswith("count clients"):
        if common.flags['d']:
            print("[*] Menu --> Count Clients")
            Authlib.countclients()
    elif msg == "kill all":
        if common.flags['d']:
            print("[*] Menu --> Kill All")
        server.terminate_all()
    elif msg.startswith("kill"):
        server.killclient(int(msg.split(" ")[1]))

    elif msg.startswith("chat"):
        if common.flags['d']:
            print("[*] Menu --> Chat")
        phrase = msg.split(" ")
        if phrase[1] == "all":
            if common.flags['d']:
                print("[*] Menu --> Chat All")
            Authlib.update()
            msg = phrase[2]
            msg = msg + "\n"
            if len(Authlib.auth_conns) == 1:
#                client = Authlib.auth_conns
                client = Authlib.auth_conns

                try:
                    client.send(msg.encode())
                    print("[*] Sent chat to",client)
                except:
                    print("[!] Unable to send message to:", Authlib.auth_conns)
                    if common.flags['d']:
                        print("[!] Error:",exc_info())
            else:
                for client in Authlib.auth_conns:

                    try:
                        client[0].send(msg.encode())
                    except:
                        print("[!] Unable to send message to:",client[0])
                        if common.flags['d']:
                            print("[!] Error:", exc_info())


