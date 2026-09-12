// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title HoneypotToken
 * @notice Test fixture containing honeypot, fee manipulation, and blacklisting vulnerabilities.
 */
contract HoneypotToken {
    string public name = "Honeypot Token";
    string public symbol = "HONEY";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 1e18;

    address public owner;
    uint256 public taxFeePercent = 15; // >10% tax fee
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public isBlacklisted;

    constructor() {
        owner = msg.sender;
        balanceOf[msg.sender] = totalSupply;
    }

    // VULNERABILITY: Arbitrary tax fee modification by owner up to 100%
    function setTaxFee(uint256 _taxFeePercent) external {
        require(msg.sender == owner, "Not owner");
        taxFeePercent = _taxFeePercent;
    }

    // VULNERABILITY: Owner can blacklist any arbitrary address from transferring
    function setBlacklist(address account, bool value) external {
        require(msg.sender == owner, "Not owner");
        isBlacklisted[account] = true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!isBlacklisted[msg.sender], "Blacklisted sender");
        require(balanceOf[msg.sender] >= amount, "Exceeds balance");

        uint256 fee = (amount * taxFeePercent) / 100;
        uint256 transferAmount = amount - fee;

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += transferAmount;
        balanceOf[owner] += fee;
        return true;
    }
}
