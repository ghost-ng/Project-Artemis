
flags = {}                  #This is a summary of the arguments


args = ''                   #This is the arguments in raw form


client_start = False      #This can be True if the client successfully started


def fixmsgformat(data):
    while data.endswith('\n'):
        data = data.rstrip('\n')
    return data