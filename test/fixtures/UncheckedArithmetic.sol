// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedArithmetic {
    mapping(address => uint256) public balances;

    function unsafeDecrement(uint256 amount) external {
        unchecked {
            balances[msg.sender] -= amount;
        }
    }

    function divisionPrecision(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        return (a / b) * c;
    }
}
