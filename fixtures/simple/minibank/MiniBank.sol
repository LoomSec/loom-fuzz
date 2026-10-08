// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Smallest non-trivial example for Loom's guard/effect walk.
contract MiniBank {
    address public owner;
    mapping(address => uint256) public ledger;

    error OnlyOwner();
    error EmptyDeposit();
    error InsufficientBalance();
    error TransferFailed();

    event Deposit(address indexed who, uint256 amount);
    event Withdraw(address indexed who, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        if (msg.value == 0) revert EmptyDeposit();
        ledger[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        if (msg.sender != owner) revert OnlyOwner();
        if (ledger[msg.sender] < amount) revert InsufficientBalance();
        ledger[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Withdraw(msg.sender, amount);
    }
}
