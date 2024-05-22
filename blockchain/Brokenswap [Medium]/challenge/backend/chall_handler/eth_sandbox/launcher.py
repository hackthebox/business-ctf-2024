#!/usr/bin/env python

import json
import os
import random
import string
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from uuid import UUID

import requests
from eth_account import Account
from web3 import Web3
from web3.exceptions import TransactionNotFound
from web3.types import TxReceipt

from eth_sandbox import get_shared_secret

SRV_PORT = os.getenv("SRV_PORT", "8000")
PUBLIC_IP = os.getenv("PUBLIC_IP", "0.0.0.0")

TEAM_UUID = os.getenv("TEAM_UUID", "team")
FLAG = os.getenv("FLAG", "HTB{1_w4sn7_7h3_0nly_7h1ng_br0k3}")

Account.enable_unaudited_hdwallet_features()

@dataclass
class Action:
    name: str
    handler: Callable[[], int]


def sendTransaction(web3: Web3, tx: Dict) -> Optional[TxReceipt]:
    if "gas" not in tx:
        tx["gas"] = 10_000_000

    if "gasPrice" not in tx:
        tx["gasPrice"] = 0

    web3.provider.make_request("anvil_impersonateAccount", [tx["from"]])
    txhash = web3.eth.sendTransaction(tx)
    web3.provider.make_request("anvil_stopImpersonatingAccount", [tx["from"]])

    while True:
        try:
            rcpt = web3.eth.getTransactionReceipt(txhash)
            break
        except TransactionNotFound:
            time.sleep(0.1)

    if rcpt.status != 1:
        raise Exception("failed to send transaction")

    return rcpt

def new_launch_instance_action(
    do_deploy: Callable[[Web3, str], str],
    getChallengeAddress: Callable[[Web3, str], str]
):
    def action() -> int:
        data = requests.post(
            f"http://127.0.0.1:{SRV_PORT}/new",
            headers={
                "Authorization": f"Bearer {get_shared_secret()}",
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "team_id": TEAM_UUID,
                }
            ),
        ).json()

        if data["ok"] == False:
            print(data["message"])
            return 1

        uuid = data["uuid"]
        mnemonic = data["mnemonic"]
        
        deployer_acct = Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/0")
        player_acct = Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/1")

        web3 = Web3(Web3.HTTPProvider(
            f"http://127.0.0.1:{SRV_PORT}/rpc/{uuid}",
            request_kwargs={
                "headers": {
                    "Authorization": f"Bearer {get_shared_secret()}",
                    "Content-Type": "application/json",
                },
            },
        ))

        setup_addr = do_deploy(web3, deployer_acct.address, player_acct.address)
        target_addr, fees_pool_addr, weth_addr, htb_addr = getChallengeAddress(web3, setup_addr)
        
        connection_info = {
            "Team UUID": TEAM_UUID,
            "Player UUID": uuid,
            "RPC URL": f"http://{PUBLIC_IP}:{SRV_PORT}/rpc/{uuid}",
            "Player Private Key": player_acct._private_key.hex(),
            "Player Address": player_acct.address,
            "Setup Contract": setup_addr,
            "Target Contract": target_addr,
            "Fees Pool Contract": fees_pool_addr,
            "WETH Token Contract": weth_addr,
            "HTB Token Contract": htb_addr,
        }

        with open(f"/tmp/{TEAM_UUID}", "w") as f:
            f.write(json.dumps(connection_info, indent=4))

        with open('/var/www/html/constants/token-list.json', 'r') as f:
            tokenList = json.load(f)
            for token in tokenList['tokens']:
                if token['symbol'] == 'HTB':
                    token['address'] = connection_info['HTB Token Contract']
                elif token['symbol'] == 'WETH':
                    token['address'] = connection_info['WETH Token Contract']

        with open('/var/www/html/constants/token-list.json', 'w') as f:
            json.dump(tokenList, f, indent=4)

        print("Your private blockchain has been deployed.")
        print("It will automatically terminate in 30 minutes.")
        print("Here's your connection info:\n")
        for key, value in connection_info.items():
            print(f"{key}: {value}")

        return 0

    return Action(name="launch new instance", handler=action)


def new_kill_instance_action():
    def action() -> int:
        data = requests.post(
            f"http://127.0.0.1:{SRV_PORT}/kill",
            headers={
                "Authorization": f"Bearer {get_shared_secret()}",
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "team_id": TEAM_UUID,
                }
            ),
        ).json()

        print(data["message"])
        return 1

    return Action(name="kill instance", handler=action)

def is_solved_checker(web3: Web3, player: str, setup: str) -> bool:
    result = web3.eth.call(
        {
            "from": player,
            "to": setup,
            "data": web3.keccak(text="isSolved()")[:4],
        }
    )
    return int(result.hex(), 16) == 1


def new_get_flag_action(
    checker: Callable[[Web3, str], bool] = is_solved_checker,
):
    def action() -> int:
        try:
            with open(f"/tmp/{TEAM_UUID}", "r") as f:
                data = json.loads(f.read())
        except:
            print("team instance not found, launch a new instance first")
            return 1

        web3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{SRV_PORT}/rpc/{data['Player UUID']}"))

        if not checker(web3, data['Player Address'], data['Setup Contract']):
            print("are you sure you solved it?")
            return 1

        print(FLAG)
        print()
        print("Well done, Vault Boy! Not many have made it this far.")
        print("Was it easy like drinking a Nuka-Cola? Well, that was a simplified version of the 340 ETH (worth approximately $624,000 at the time) LeetSwap Hack that occurred on August 1, 2023.")
        print("Congratulations, you could have been rich now ☢️")
        return 0

    return Action(name="get flag", handler=action)


def run_launcher(actions: List[Action]):
    for i, action in enumerate(actions):
        print(f"{i+1} - {action.name}")

    action = input("action? ")
    if not action.isdigit() or int(action) <= 0 or int(action) > len(actions):
        print("can you not")
        exit(1)

    status_code = actions[int(action)-1].handler()
    exit(status_code)