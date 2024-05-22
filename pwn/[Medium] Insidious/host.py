#!/usr/bin/env python3

import socket
import os
import subprocess
import sys

PORT = 1337
DOCKER_IMAGE = 'insidious'

def check_pow(client_socket):
    if not os.path.exists("./check-pow"):
        return True
    try:
        pow_process = subprocess.Popen(
            ["./check-pow"],
            stdin=client_socket.fileno(),
            stdout=client_socket.fileno(),
            stderr=client_socket.fileno(),
            bufsize=0
        )
        if pow_process.wait() == 0:
            return True
        else:
            client_socket.close()
            return False
    except Exception:
        return False
    finally:
        pow_process.terminate()

def handle_client(client_socket):
    if not check_pow(client_socket):
        return
    try:
        container_process = subprocess.Popen(
            ["timeout", "-k0", "2m",
            "docker", "run",
            "-i", DOCKER_IMAGE],
            stdin=client_socket.fileno(),
            stdout=client_socket.fileno(),
            stderr=client_socket.fileno(),
            bufsize=0
        )
        container_process.wait()
    finally:
        client_socket.close()
        container_process.terminate()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', PORT))
    server_socket.listen(32)
    
    print(f"Server listening on port {PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        pid = os.fork()
        if pid == 0:
            server_socket.close()
            handle_client(client_socket)
            sys.exit(0)
        else:
            client_socket.close()

if __name__ == "__main__":
    main()