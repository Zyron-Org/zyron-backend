// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title UnprotectedInitializer
 * @notice Test fixture containing unprotected proxy initialization vulnerability.
 */
contract UnprotectedInitializer {
    address public owner;
    bool public initialized;

    event Initialized(address indexed owner);

    // VULNERABILITY (SWC-118): Unprotected initializer missing initializer guard or owner check
    function initialize(address _owner) external {
        // Missing require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
        emit Initialized(_owner);
    }

    // VULNERABILITY (SWC-112): Delegatecall to untrusted user input address
    function executeDelegateCall(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == owner, "Not owner");
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }
}
