pragma solidity 0.8.25;

contract Recruitment {
    constructor() payable {}

    mapping (address => bool) public crew;

    function isRecruited(address _candidate) public view returns (bool) {
        return crew[_candidate];
    }

    function application(uint16 input1, string memory input2) public {
        // In order to be eligible, you must match the following set of skills:
        // - Hacker
        // - Stealth Specialist
        // - Engineer
        // - Demolition Specialist

        // Let's start!
        // Some preliminary checks: we do not hire unlucky people.
        require(block.timestamp % 2 == 0, "Natural selection people say..");

        // CAPTCHA (Completely Automated Public Turing test to tell Computers and Humans Apart)
        require(tx.origin == msg.sender, "Are you even human?");

        // Now let's start for real.
        // 1. Are you an hacker?
        require(input1 == 1337, "You lack hacking skills.");
        // yeah you definitely are.

        // 2. Are you stealthy?
        require(block.number < 20, "You lack stealth skills.");

        // 3. Are you an engineer?
        require(gasleft() <= 50000, "You lack engineering skills.");

        // 4. Are you a demolition specialist?
        require(keccak256(abi.encodePacked(input2)) == keccak256(abi.encodePacked("BOOM")), "You lack demolition skills.");

        // Congratulations! Welcome to the crew.
        crew[msg.sender] = true;
        // here is your reward :)
        payable(msg.sender).transfer(1 wei);
        }
}