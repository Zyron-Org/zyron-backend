// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReentrancyVault
 * @notice Test fixture containing deliberate reentrancy and access control vulnerabilities.
 */
contract ReentrancyVault {
    mapping(address => uint256) public balances;
    bool private locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULNERABILITY (SWC-107): State change after external call
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // Vulnerable: state updated after transfer
        balances[msg.sender] = 0;
        emit Withdraw(msg.sender, balance);
    }

    // VULNERABILITY (SWC-105): Unprotected tx.origin check
    function emergencyWithdrawAll() external {
        require(tx.origin == msg.sender, "Only EOA allowed");
        payable(msg.sender).transfer(address(this).balance);
    }
}
