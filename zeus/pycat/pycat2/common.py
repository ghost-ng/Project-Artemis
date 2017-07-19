
flags = {}  #This is a summary of the arguments
args = ''   #This is the arguments in raw form
authenticated_token = ''    #The token used to prove authentication

def fixmsgformat(data):
    while data.endswith('\n'):
        data = data.rstrip('\n')
    return data