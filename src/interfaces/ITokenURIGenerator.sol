// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

interface ITokenURIGenerator {
    function buildTokenURI(
        uint256 tokenId,
        uint256 fid,
        bool claimed
    ) external pure returns (string memory);
}
