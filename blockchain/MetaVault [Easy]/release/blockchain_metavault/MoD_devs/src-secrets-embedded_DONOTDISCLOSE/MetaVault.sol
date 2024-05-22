// SPDX-License-Identifier: MoD-Internal-v1.0
pragma solidity 0.8.25;

/**
 * @title MetaVault
 * @author Ministry of Defense
 * @notice MoD (Ministry of Defense) Smart Contract storing the country's ETH reserves.
 */
contract MetaVault {
    /**
     * @notice Keccak256 hashed secret passphrase to enable emergency mode.
     * @dev plaintext secret: [REDACTED] 
     * @dev The secret will be stripped before open sourcing the code. Comments are not compiled anyway.
     */ 
    bytes32 constant private VAULT_SECRET_K256 = 0x42c10591ced4987005f70d29b498348ecc8ab18dd28c5b93db931375ca826b5e; 
    
    event Deposit(
        address indexed _from,
        uint256 indexed _value,
        uint256 indexed _updatedBalance
    );
    event FailedLoginAttempt(
        address indexed _from,
        string  indexed _attempt,
        bytes32 indexed _hashedAttempt
    );
    event EmergencyMode(
        address indexed _by,
        address indexed _fundsDestination
    ); 

    /**
     * @dev Retrieves the current ETH balance of the vault.
     * @return balance of the vault in wei.
     */
    function getVaultBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Deposit function to receive ETH deposits.
     * @dev emits a Deposit event with the depositor, the value deposited and the updated balance after deposit.
     */
    function deposit() public payable {
        emit Deposit(
            msg.sender,
            msg.value,
            getVaultBalance()
        );        
    }

    /**
     * @notice Function to fire the emergency mode by selfdestructing the contract and transfering the funds away.
     * @param _secret The secret passphrase required to activate emergency mode.
     * @dev The secret is shared only to MoD devs.
     */
    function emergency(string memory _secret) external {
        bytes32 attempt_k256 = keccak256(bytes(_secret));
        if (attempt_k256 == VAULT_SECRET_K256) {
            emit EmergencyMode(msg.sender, msg.sender);
            selfdestruct(payable(msg.sender));
        } else {
            emit FailedLoginAttempt(msg.sender, _secret, attempt_k256);
        }
    }
}
