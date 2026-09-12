// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

/**
 * @title OracleManipulator
 * @notice Test fixture containing spot price oracle manipulation vulnerability.
 */
contract OracleManipulator {
    address public pool;

    constructor(address _pool) {
        pool = _pool;
    }

    // VULNERABILITY (SWC-116 / Spot Price Manipulation): Uses getReserves() directly for collateral valuation
    function getAssetPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(pool).getReserves();
        require(reserve0 > 0, "Empty reserve");
        // Direct spot price calculation - highly vulnerable to flash loan manipulation
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    // VULNERABILITY (SWC-116 / Timestamp Dependence): Block timestamp used for financial calculation logic
    function isTradeAllowed() public view returns (bool) {
        return block.timestamp % 15 == 0;
    }
}
