import socket
import json
import binascii
import struct
import copy
import subprocess
from pwn import args

if args.REMOTE:
    IP, PORT = args.HOST.split(":")
else:
    IP = '127.0.0.1'
    PORT = 1337


class FirmwarePart:

    def __init__(self, name, offset, size):
        self.name = name
        self.offset = offset
        self.size = size


def exchange(hex_list, value=0):

    # Configure according to your setup
    cs = 0  # /CS on A*BUS3 (range: A*BUS3 to A*BUS7)

    usb_device_url = 'ftdi://ftdi:2232h/1'

    # Convert hex list to strings and prepare the command data
    command_data = {
        "tool": "pyftdi",
        "cs_pin": cs,
        "url": usb_device_url,
        "data_out":
        [hex(x) for x in hex_list],  # Convert hex numbers to hex strings
        "readlen": value
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((IP, int(PORT)))

        # Serialize data to JSON and send
        s.sendall(json.dumps(command_data).encode('utf-8'))

        # Receive and process response
        data = b''
        while True:
            data += s.recv(1024)
            if data.endswith(b']'):
                break

        response = json.loads(data.decode('utf-8'))
        #print(f"Received: {response}")
    return response


def format_print(log_entry):
    hex_list = [f'{num:02x}' for num in log_entry]
    formatted_hex_string = ' '.join(hex_list)
    print(formatted_hex_string.upper())


def append_crc(data):
    # Calculate CRC32 of the data and return it as unsigned int
    crc = binascii.crc32(data) & 0xffffffff
    # Append CRC32 to the data
    return data + struct.pack('I', crc)


firmware = exchange([0x03, 0x00, 0x00, 0x00], 12000000)

with open("firmware.bin", "wb") as f:
    f.write(bytes(firmware))

squashfs = FirmwarePart("squashfs_1", 0x200040, 0x350000)

with open("firmware.bin", "rb") as f:
    f.seek(squashfs.offset, 0)
    data = f.read(squashfs.size)

with open(squashfs.name, "wb") as f:
    f.write(data)

print(f"Wrote {squashfs.name} - {hex(len(data))} bytes")

command = f"unsquashfs -d squashfs_1.out {squashfs.name}"
result = subprocess.run(command,
                        shell=True,
                        check=True,
                        stdout=subprocess.PIPE)

with open("squashfs_1.out/etc/init.d/rcS") as f:
    lines = f.readlines()

for line in lines:
    if "HTB" in line:
        print(line.strip()[2:])
        break
