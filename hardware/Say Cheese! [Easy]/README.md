![img](assets/banner.png)

<img src='assets/images/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>Say Cheese!</font>

28<sup>th</sup> 2022 / Document No. D22.102.16

Prepared By: `WizardAlfredo`

Challenge Author(s): `WizardAlfredo`

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

- Review the datasheet of the flash memory chip, extract the camera firmware, and analyze it to find the backdoor.

## Description

- The crew's humanitarian mission attracts the ire of the Enclave, who deploys drones to monitor their efforts. In a stroke of luck, the crew manages to shoot down one of the drones. Seizing the opportunity, they bring the drone back to their workshop and carefully disassemble it. The drone's components are numerous, but the camera stands out as it is a seperate module. Scanning the camera with Nmap reveals it runs Telnet, though it's password-protected. Analyzing the chips, they identify a flash memory similar to the W25Q128 family. The crew's tech specialist examines the device closely. The goal: to hijack the drones and thwart the Enclave's surveillance and attacks.

## Skills Required

- Basic documentation analysis.
- Basic research skills.

## Skills Learned

- Analyzing hardware component documentation.
- Using flash memory instructions to read its contents.
- Analyzing firmware and extracting the filesystem.

# Enumeration

In this challenge, we are provided with one file:

- `client.py` : A client file that allows interaction with the flash memory chip using a socket connection.

## Analyzing the flash memory's Datasheet

There is an excellent writeup about this exact memory chip explained in another challenge we did for CA 2024 called Rids. You can find it [here](https://github.com/hackthebox/cyber-apocalypse-2024/blob/main/hw/Rids%20%5BEasy%5D/README.md). We will use the same method to **read** the **firmware**, but instead of reading only a few bytes, we will read the entire memory.

# Solution

## Exploitation

### Connecting to the server

A pretty basic script for connecting to the server with `pwntools`:

```python
if __name__ == "__main__":
    r = remote("0.0.0.0", 1337)
    pwn()
```

### Reading the firmware

Using the provided `client.py`, add the following line:

```python
firmware = exchange([0x03, 0x00, 0x00, 0x00], 16000000)
```

This process may take some time, as we are downloading 16MB of data. After 4 to 5 minutes, we should have all the firmware. Next, write the firmware to a file:

```python
with open("firmware.bin", "wb") as f:
    f.write(bytes(firmware))
```

### Extracting the filesystem

Simply running:

```bash
binwalk -e firmware.bin
```

will extract all the important data. However, for more educational value, let's extract it manually. First, identify the **partitions** and **extract** the **important** ones with some scripting. Start with `binwalk`:

```bash
binwalk -t firmware.bin
```

The results

```bash
0             0x0             uImage header, header size: 64 bytes, header CRC: 0x562C89CA, created:
                              2024-05-15 11:48:58, image size: 11075584 bytes, Data Address: 0x0,
                              Entry Point: 0x0, data CRC: 0xE89A0BAD, OS: Linux, CPU: MIPS, image
                              type: Firmware Image, compression type: none, image name: "jz_fw"
64            0x40            uImage header, header size: 64 bytes, header CRC: 0x6F5948F4, created:
                              2020-05-26 05:03:55, image size: 1907357 bytes, Data Address:
                              0x80010000, Entry Point: 0x80421870, data CRC: 0xD8FCDDFA, OS: Linux,
                              CPU: MIPS, image type: OS Kernel Image, compression type: lzma, image
                              name: "Linux-3.10.14"
.
.
.
<SNIP>
.
.
.
2097216       0x200040        Squashfs filesystem, little endian, version 4.0, compression:xz, size:
                              3289996 bytes, 414 inodes, blocksize: 131072 bytes, created: 2024-05-15
                              11:42:45
5570624       0x550040        Squashfs filesystem, little endian, version 4.0, compression:xz, size:
                              593566 bytes, 13 inodes, blocksize: 131072 bytes, created: 2020-08-20
                              09:14:54
6225984       0x5F0040        JFFS2 filesystem, little endian
.
.
.
<SNIP>
.
.
.
```

For this challenge, we can focus on the first **Squashfs** filesystem. Isolate it as follows:

```python
class FirmwarePart:

    def __init__(self, name, offset, size):
        self.name = name
        self.offset = offset
        self.size = size

squashfs = FirmwarePart("squashfs_1", 0x200040, 0x350000)

with open("firmware.bin", "rb") as f:
    f.seek(squashfs.offset, 0)
    data = f.read(squashfs.size)

with open(squashfs.name, "wb") as f:
    f.write(data)
```

It is still a Squashfs filesystem, so we need to **unsquash** it to read its contents. Use the `unsquashfs` tool:

```python
command = f"unsquashfs -d squashfs_1.out {squashfs.name}"
result = subprocess.run(command,
                        shell=True,
                        check=True,
                        stdout=subprocess.PIPE)
```

### Analyzing the firmware

With the firmware extracted, **search** for the **flag** using `ripgrep` or navigate to the filesystem to find it under `/etc/init.d/rcS`.

```txt
# Start telnet daemon
# https://www.youtube.com/watch?v=hV8W4o-Mu2o
# <SNIP>
busybox telnetd &
```

Automate this process with Python:

```python
with open("squashfs_1.out/etc/init.d/rcS") as f:
    lines = f.readlines()

for line in lines:
    if "HTB" in line:
        print(line.strip()[2:])
        break
```

### Getting the flag

To summarize:

1. Read the chip's documentation.
2. Read the firmware from memory.
3. Extract the relevant partitions.
4. Unsquash the filesystem.
5. Read the flag.
