BLUE = '\033[94m'
GREEN = '\033[92m'
RED = '\033[31m'
YELLOW = '\033[93m'
FAIL = '\033[91m'
RSTCOLORS = '\033[0m'
BOLD = '\033[1m'
BGRED = '\033[41m'
WHITE = '\033[37m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'

FAILED = "FAILED"
WARN = "WARN"
SUCCESS = "SUCCESS"
INFO = "INFO"


def PrintColor(status, msg, result="", ARROW_LENGTH=10):
    '''
    Prints out the message in a pre-formatted string of text
    Possible values for 'status': WARN,SUCCESS,FAIL,INFO
    '''
    if status == "WARN":
        text = YELLOW + "[!] " + msg + " " + PrintArrow(ARROW_LENGTH) + " " + result + RSTCOLORS
    elif status == "SUCCESS":
        text = GREEN + "[+] " + msg + " " + PrintArrow(ARROW_LENGTH) + " " + result + RSTCOLORS
    elif status == "INFO":
        text = WHITE + "[*] " + msg + RSTCOLORS
    elif status == "FAILED":
        text = RED + "[-] " + msg + " " + PrintArrow(ARROW_LENGTH) + " " + result + RSTCOLORS
    else:
        text = "[*] " + msg + PrintArrow(ARROW_LENGTH) + " " + result + RSTCOLORS
    print(text)

    # print("test")


def PrintArrow(length):
    count = 0
    arrow = ''
    while count < length:
        arrow = arrow + '-'
        count = count + 1
    arrow = arrow + '>'
    return arrow
