import Authlib

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
        print("")
        print("Help Menu:")
        for item in help_menu:
            print(item)
    elif "help " in msg:
        for item in help_menu:
            if msg.split(" ")[1] in item:
                print(item)
    elif msg == "update":
        Authlib.listclients()
    elif msg == "show clients":
        Authlib.listclients()
        Authlib.listauthenticated()
    elif msg.startswith("show clients"):        #Options show clients [connected,authenticated]
        cmd = msg.split(" ")
        if len(cmd)== 2:
            print("[*] Connected Clients:")
            Authlib.listclients()
            print("[*] Authenticated Clients:")
            Authlib.listauthenticated()
        elif cmd[2] == "connected":
            Authlib.listclients()
        elif cmd[2] == "authenticated":
            Authlib.listauthenticated()
    elif msg.startswith("count clients"):
            Authlib.countclients()
    elif msg == "kill all":
        server.terminate_all()
    elif msg.startswith("kill"):
        server.killclient(int(msg.split(" ")[1]))

    elif msg.startswith("chat"):
        cmd = msg.split(" ")
        if cmd[1] == "all":
            Authlib.update()
            msg = cmd[2]
            for client in Authlib.clients:
                msg = msg + "\n"
                try:
                    client[0].send(msg.encode())
                except:
                    print("[!] Unable to send message to:",client[0])


