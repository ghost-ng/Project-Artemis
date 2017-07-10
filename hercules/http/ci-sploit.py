def startup():
    pass


def ValidateInput(inputted_cmds, avail_cmds_list):
    #checking list 1 for compliance with list 2
    #avail_cmds = [
    #    "set", ("target", ["interval", "retry", "shodan_list", "target_file"]), ("shodan",
    #    ["query", "username", "password"]),
    #    "load", ["module"]
    #           ]

    for cmd in inputted_cmds:



def Iterate(li,value):




def GetInput():
    # Possible Options:
    #
    #   set target interval
    #   set target retry
    #
    #   USING SHODAN QUERIES TO FIND TARGETS:
    #   set target shodan_list
    #   set shodan query [query]
    #   set shodan username [username]
    #   set shodan password [password
    #
    #   USING IP LIST FOR TARGETS
    #   set target_file [filename]
    #
    #   LOAD A MODULE
    #   load [module]
    #
    #   SHOW OPTIONS:
    #   show options
    #   run

    avail_cmds = [
        "set", "target", ["interval", "retry", "shodan_list", "target_file"], "shodan",
        ["query", "username", "password"],
        "load", ["module"]]
    feedback = input("ci-sploit>>")

    # VERIFY COMMANDS
    feedback_chunk = feedback.split(" ")
    ValidateInput(feedback_chunk, avail_cmds)


if __name__ == '__main__':
    GetInput()
