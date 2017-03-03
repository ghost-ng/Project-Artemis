import argparse
import sys
import telnetlib


def tryAuth(HOST, PORT, USER, PASSWORD):
    tn = telnetlib.Telnet(HOST, PORT)
    tn.read_until("login: ".encode()).decode()
    tn.write(USER + "")
    tn.read_until("Password: ")
    tn.write(PASSWORD + "")

    for x in range(5, 9001):
        print("[*] Trying Option:", x)
        tn.write(str(x).encode() + b"\n")
        response = tn.read_until("selection:".encode()).decode()
        if response != '\n% Enter your selection:':
            print("[+] Found a new option:", x)
            break

    tn.close()


def parse_args():
    if not len(sys.argv[1:]):
        print("[*] Did not detect any options")
        print("[*] Try [script] -h or --help to view the help menu")
        sys.exit(0)
    else:

        parser = argparse.ArgumentParser(description="telnet bruteforce tool")
        parser.add_argument('-p', '--port', action='store', dest='port', type=str, required=True,
                            metavar="[Target Port(s)]", help='Remote Port; can also be a range: "1-10"')
        parser.add_argument('-h', '--host', action='store', dest='host', type=str, required=True,
                            metavar="[Remote Host]", help='Remote Host')
        args = parser.parse_args()
        return args


def main():
    args = parse_args()
    try:
        PORT = int(args.port)
    except:
        PORTS_ARRAY =
    tryAuth(args.host, args.port)
