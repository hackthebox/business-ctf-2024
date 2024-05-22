#!/usr/bin/env python3

import logging
logging.basicConfig(filename='/var/log/ctf/gunicorn.error.log', level=logging.ERROR,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger=logging.getLogger(__name__)

try:
    import json
    from pathlib import Path
    import eth_sandbox
    from web3 import Web3


    def deploy(web3: Web3, deployer_address: str, player_address: str) -> str:
        web3.provider.make_request("anvil_setBalance", [deployer_address, hex(Web3.to_wei(511, 'ether'))])
        contract_interface = json.loads(Path("/home/ctf/backend/compiled-contracts/Setup.sol/Setup.json").read_text())
        bytecode = contract_interface['bytecode']['object']
        abi = contract_interface['abi']
        Setup = web3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = Setup.constructor(player_address).transact(transaction={'from': deployer_address, 'value': Web3.to_wei(510, 'ether')})
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address = tx_receipt['contractAddress']

        return contract_address

    def getChallengeAddress(web3: Web3, address):
        abi = json.loads(Path("/home/ctf/backend/compiled-contracts/Setup.sol/Setup.json").read_text())["abi"]
        setupContract = web3.eth.contract(address=address, abi=abi)
        targetAddress = setupContract.functions.TARGET().call()
        wethAddress = setupContract.functions.weth().call()
        htbAddress = setupContract.functions.htb().call()
        feesPoolAddress = setupContract.functions.feesPool().call()

        return targetAddress, feesPoolAddress, wethAddress, htbAddress

    eth_sandbox.run_launcher([
        eth_sandbox.new_launch_instance_action(deploy, getChallengeAddress),
        eth_sandbox.new_kill_instance_action(),
        eth_sandbox.new_get_flag_action()
    ])

except Exception as e:
    print("Ops, something went wrong :(")
    print("Please contact support, will be fixed ASAP.")
    print("Here's a funny cats compilation while you wait: https://youtu.be/DHfRfU3XUEo?si=fIIwgJYnaKcp_ZUV&t=55")
    logger.error(e)