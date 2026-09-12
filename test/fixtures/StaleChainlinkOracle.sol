// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function latestAnswer() external view returns (int256);
}

contract StaleChainlinkOracle {
    AggregatorV3Interface public priceFeed;

    function getUnvalidatedPrice() external view returns (int256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        return price;
    }

    function getDeprecatedPrice() external view returns (int256) {
        return priceFeed.latestAnswer();
    }
}
