import argparse
import sys
import Authlib
import common
import ClientHandler,Client,ServerOptions
from time import sleep


def getArgs():

    parser = argparse.ArgumentParser(description="Peer to Peer chat client",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog='''Examples:
            Server:   script.py -l 0.0.0.0 -p 9999
                      script.py -l localhost -p 4444 -k [shell]
            Client:   script.py -r 10.0.1.5 -p 4444 -e '/tmp/backdoor.sh'
                      script.py -r 79.86.48.22 -p 4444

            Note:     This is not a TTY terminal and interactive commands like sudo
                      and vi will not work''')
    group = parser.add_mutually_exclusive_group()
    parser.add_argument('-l', '--listen', action='store', dest='listening_addr', const="0.0.0.0",
                        nargs="?", help='Local address to listen on', metavar="[Listening Address]")
    parser.add_argument('-p', '--port', action='store', dest='port', type=int, required=True,
                        metavar="[Target Port]",
                        help='Local port to bind to')
    group.add_argument('-r', '--remote-host', action='store', dest='remote_host', metavar="[Remote Host]",
                       help='Remote IP to connect to')
    group.add_argument('-s', '--shell', action='store_true', dest='shellflg',
                       help='Spawn a shell')
    parser.add_argument('--exec-keyword', action='store', dest='exec_keyword', metavar="[Keyword]",
                        default='[exec]',
                        help='The keyword at the beginning of a command to instruct the server to process the'
                             'following string as a command.  Default is "[exec]"   '
                             'Example: [exec] ls -al  --> "[exec]" becomes the parameter for this argument and'
                             'instructs the server to interpret the subsequent strings as shell commands.'
                             'Note: This is a server side argument')
    parser.add_argument('-e', '--execute', action='store', dest='execute', metavar="[Command to Execute]", default=False,
                        help="execute a command; stdout/err is not received on client from any spawned processes")
    parser.add_argument('-u', '--upload', action='store', dest='upload', metavar="[Upload Destination]",
                        help='upload a file; combined with -e it will upload and execute the file')
    parser.add_argument('--upload-keyword', action='store', dest='upload_keyword', metavar="[Keyword]",
                        default='[upload]',
                        help='Change the keyword to instruct the server to upload a file.  Default: "[upload]"')
    parser.add_argument('--run', action='store_true', dest='run',
                        help='Will tell the server side script to execute the uploaded file')
    parser.add_argument('-d', '--debug', action='store_true', dest='debugflg',
                        help='Turn on verbose feedback')
    parser.add_argument('-q', '--quiet', action='store_true', dest='quietflg',
                        help='Supress all error messages; should not be used with -d;'
                             'verbocity lvls = debug --> no options --> quiet')
    parser.add_argument('-a', '--auth', action='store_true', dest='auth',default=None,
                        help='If a client, prompt for the password to authenticate with the server.'
                             'If a server, prompt for a password to authenticate clients.')
    parser.add_argument('-k', '--key', action='store', dest='key', default=None,
                        help='Store the string either as the server authentication token or as a '
                             'token for the client to authenticate with')
    args = parser.parse_args()

    try:
        len(args.listening_addr)
        listenflg = True
    except:
        listenflg = False

    try:
        len(args.upload)
        upload = args.upload
    except:
        upload = False


    common.flags = {"l": listenflg, "p": args.port, "r": args.remote_host, "u": upload,
             "upload-keyword": args.upload_keyword, "s": args.shellflg,
             "e": args.execute, "exec-keyword": args.exec_keyword, "run": args.run, "q": args.quietflg,
             "d": args.debugflg, "auth": args.auth, "key": args.key}

    return args

def main(args):
    version = sys.version_info[0]


    if common.flags['l'] and not common.flags['r']:  # Run the server
        run_server = ClientHandler.ConnectionThread(args.listening_addr, args.port)
        run_server.start()
        if common.flags['auth'] and not common.flags['key']:
            try:
                Authlib.PromptPasswd()
            except:
                sys.exit(0)
        if common.flags['d']:
            print("""
DEGUG INFO:

Flags:
{f}
AuthLib:
Server Token: {s}""".format(f=common.flags, s=Authlib.server_auth_token))
            input("\nPress any key to run\n")
            print("[+] Listening...")
        while True:
            try:

                if int(version) > 2:
                    msg = input("")
                else:
                    msg = raw_input("")
            except KeyboardInterrupt:
                if not common.flags['q']:
                    print("[!] Keyboard Interrupt Detected")
                run_server.terminate_all()
                sys.exit()
            except (ConnectionError, ConnectionAbortedError):
                if not common.flags['q']:
                    print("[*] Connection Dropped...")
                if not common.flags['q'] or common.flags['d']:
                    print("[*] Error:", sys.exc_info())
                sys.exit()
            ServerOptions.resolveOpts(msg,run_server)


    elif common.flags['r'] and not common.flags['l']:  # Run the client

        try:
            client = Client.Client(args.remote_host, args.port)
            common.client_start = True
        except:
            print("[!] Unable to Establish a Connection...")
            print("[*] Check Your Address Arguments -r {h} -p {p}".format(h=args.remote_host, p=args.port))
        sleep(1)
        if common.flags['d']:
            print("[*] Client Startup:",common.client_start)

        if common.client_start == True:
            client.start()
        else:
            if not common.flags['q']:
                print("[!] Unable to Establish a Connection...")
                print("[*] Check Your Address Arguments -r {h} -p {p}".format(h=args.remote_host, p=args.port))
            sys.exit(0)

        if common.flags['auth']:
            try:
                Authlib.PromptPasswd()
            except:
                sys.exit(0)
        client.send_msg("[auth]" + Authlib.client_auth_token)


        while not common.flags['e'] and not common.flags['u']:
            try:
                if int(version) > 2:
                    msg = input("pycat >> ")
                else:
                    msg = raw_input("pycat >> ")
                if msg == "exit":
                    break

                client.send_msg(msg)
                sleep(.5)
            except KeyboardInterrupt:
                print("\n[*] Keyboard Interrupt Detected!  Quitting...")
                client.tcp_client.close()
                #client.stop()

                sys.exit(0)
            except:
                if common.flags['d']:
                    print(sys.exc_info())
        sys.exit(0)

if __name__ == '__main__':
    BANNER_ART = """
        ______      _____       _   
        | ___ \    /  __ \     | |  
        | |_/ /   _| /  \/ __ _| |_ 
        |  __/ | | | |    / _` | __|
        | |  | |_| | \__/\ (_| | |_ 
        \_|   \__, |\____/\__,_|\__|
               __/ |                
              |___/                 

                  |\      _,,,,--,,_
                  /,`.-'`'    -,  \-;,
                 |,4-  ) ),,__ ,\ (  ;;        
                '---''(.'--'  `-'`.)`'  v1.3

    A python implementation of netcat"""

    if not len(sys.argv[1:]):
        print(BANNER_ART)
        print("   Use -h or --help for the help menu")

        sys.exit(0)
    main(getArgs())
    sys.exit()