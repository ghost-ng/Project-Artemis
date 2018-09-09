import Authlib,common
from sys import exc_info
help_menu = [
"""show clients
    --> List all clients
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
    elif msg == "show clients":
        if common.flags['d']:
            print("[*] Menu --> Show Clients")
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
        if msg == "chat all":
            phrase = msg.split(" ")
            if common.flags['d']:
                print("[*] Menu --> Chat All")
            Authlib.update()
            msg = phrase[2]
            msg = input("pycat >>") + "\n"
            for client in Authlib.clients:
                try:
                    client[0].send(msg.encode())
                    peer = str(client[0].getpeername()[0]) + ":" + str(client[0].getpeername()[1])
                    if common.flags['d']:
                        print("[*] Chat Sent --> {}".format(peer))
                except:
                    print("[!] Unable to send message to:",client[0])
                    if common.flags['d']:
                        print("[!] Error:", exc_info())