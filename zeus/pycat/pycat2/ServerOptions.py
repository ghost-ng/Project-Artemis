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
    --> refresh the client list
""",
"""kill all
    --> Terminate all the connected clients
""",
"""kill [id]
    --> Terminate a select client.  ID is found with 'show clients'.
""",
"""chat [id] [message]
    --> send a message to a specific client.  ID is found with 'show clients'.
""",
"""[message]
    --> Send a message to all connected clients
""",
"""exec all [command]
    --> send a command to all connected clients.
""",
"""exec [id] [command]
    --> send a command to a specific client.  ID is found with 'show clients'.
""",
"""help
    --> View the help menu
""",
"""help [keyword]
    -->Display specific help topics
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
        string = msg.split(" ")
        if string[2] == "connected":
            Authlib.listclients()
        elif string[2] == "authenticated":
            Authlib.listauthenticated()
    elif msg.startswith("count clients"):
            Authlib.countclients()
    elif msg == "kill all":
        server.terminate_all()
    elif msg.startswith("kill"):
        server.killclient(int(msg.split(" ")[1]))

    else:
        for client in Authlib.clients:
            msg = msg + "\n"
            Authlib.update()
            client[0].send(msg.encode())
            print(1)
            print(client)

