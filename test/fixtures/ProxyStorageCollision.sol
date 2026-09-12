// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UpgradeableBase {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
}

contract ProxyStorageCollision is UpgradeableBase {
    uint256 public value;

    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "Delegatecall failed");
    }
}
