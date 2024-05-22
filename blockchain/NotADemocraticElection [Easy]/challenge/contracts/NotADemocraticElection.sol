pragma solidity 0.8.25;

contract NotADemocraticElection {
    // ****************************************************
    // ******* NOTE: THIS NOT A DEMOCRATIC ELECTION *******
    // ****************************************************

    uint256 constant TARGET_VOTES = 1000e18;

    struct Party {
        string  fullname;
        uint256 totalvotes;
    }
    struct Voter {
        uint256 weight;
        address addr;
    }

    mapping(bytes3 _id => Party) public parties;
    mapping(bytes _sig => Voter) public voters;
    mapping(string _name => mapping(string _surname => address _addr)) public uniqueVoters;
    bytes3 public winner;

    event Voted(
        address _voter,
        bytes3  _party
    );
    event VoterDeposited(
        address _voter,
        uint256 _weight
    );
    event ElectionWinner(
        bytes3 _party
    );

    constructor(
       bytes3 _partyAsymbol , string memory _partyAfullname,
       bytes3 _partyBsymbol , string memory _partyBfullname
    ) {
        parties[_partyAsymbol].fullname = _partyAfullname;
        parties[_partyBsymbol].fullname = _partyBfullname;
    }

    function getVotesCount(bytes3 _party) public view returns (uint256) {
        return parties[_party].totalvotes;
    }
    
    function getVoterSig(string memory _name, string memory _surname) public pure returns (bytes memory) {
        return abi.encodePacked(_name, _surname);
    }

    function checkWinner(bytes3 _party) public {
        if (parties[_party].totalvotes >= TARGET_VOTES) {
            winner = _party; 
            emit ElectionWinner(_party);
        }
    }

    function depositVoteCollateral(string memory _name, string memory _surname) external payable {
        require(uniqueVoters[_name][_surname] == address(0), "Already deposited");

        bytes memory voterSig = getVoterSig(_name, _surname);
        voters[voterSig].weight += msg.value;
        uniqueVoters[_name][_surname] = msg.sender;

        emit VoterDeposited(msg.sender, msg.value);
    }

    function vote(
        bytes3 _party,
        string memory _name,
        string memory _surname
    ) public {
        require(uniqueVoters[_name][_surname] == msg.sender, "You cannot vote on behalf of others.");

        bytes memory voterSig = getVoterSig(_name, _surname);
        uint256 voterWeight = voters[voterSig].weight == 0 ? 1 : voters[voterSig].weight;
        parties[_party].totalvotes += 1 * voterWeight;
        
        emit Voted(msg.sender, _party);
        checkWinner(_party);
    }
}