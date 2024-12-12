// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Counter is Ownable {
    uint256 public number;
    string[] private loremArray = ["Lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit", "sed", "do"];

    constructor(address initialOwner) Ownable(initialOwner){

    }
    
    modifier costs(uint256 amount) {
        require(msg.value >= amount, "Insufficient Ether provided.");
        _;
    }

    function setNumber(uint256 newNum) public onlyOwner {
        number = newNum;
    }

    function getNumber() public view returns (uint256) {
        return number;
    }

    function firstNumElements() public payable costs(0.001 ether) {
        require(number <= loremArray.length, "Number exceeds array length.");
    }

    function lastNumElements() public payable costs(0.002 ether) {
        require(number <= loremArray.length, "Number exceeds array length.");
    }

    function getFirstNumElements() public view returns (string[] memory) {
        string[] memory sliced = new string[](number);
        for (uint256 i = 0; i < number; i++) {
            sliced[i] = loremArray[i];
        }
        return sliced;
    }

    function getLastNumElements() public view returns (string[] memory) {
        uint256 slicedLength = loremArray.length - number;
        string[] memory sliced = new string[](slicedLength);
        for (uint256 i = number; i < loremArray.length; i++) {
            sliced[i - number] = loremArray[i];
        }
        return sliced;
    }

    function increment() public onlyOwner {
        number++;
    }

    function withdrawFunds() public onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }

    receive() external payable {}
}
