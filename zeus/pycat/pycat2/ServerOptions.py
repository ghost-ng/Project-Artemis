
help_menu = [
"""show clients
    --> List all connected clients
""",
"""count clients
    --> Show the total # of connected clients
""",
"""kill all
    --> Terminate all the connected clients
""",
"""kill [id]
    --> Terminate a select client.  ID is found with 'show clients'.
""",
"""chat [id] [message]
    --> dend a message to a specific client.  ID is found with 'show clients'.
""",
"""[message]
    --> Send a message to all connected clients
""",
"""help
    --> View the help menu
"""
]

def resolveOpts(msg,server):
    if msg == "help":
        print("")
        print("Help Menu:")
        for item in help_menu:
            print(item)

    elif msg.startswith("show clients"):
        server.listclients()
    elif msg.startswith("count clients"):
        server.countclients()
    elif msg == "kill all":
        server.terminate_all()
    elif msg.startswith("kill"):
        server.killclient(int(msg.split(" ")[1]))

    else:
        for c in server.clients:
            c[0].send_msg(msg + "\n")