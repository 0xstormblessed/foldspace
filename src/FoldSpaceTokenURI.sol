// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

/// @title FoldSpaceTokenURI
/// @notice Contract for generating token URIs for FoldSpace NFTs
contract FoldSpaceTokenURI {
    using Strings for uint256;

    function encodeBase64(
        string memory data
    ) internal pure returns (string memory) {
        return Base64.encode(bytes(data));
    }

    function generateSVG(
        uint256 fid,
        uint256 tokenID,
        bool claimed
    ) internal pure returns (string memory) {
        // Consolidate fillColor and opacity into a single string construction step to reduce local variables
        string memory attributes = string(
            abi.encodePacked(
                'fill="',
                claimed ? "#855DCD" : "#D3D3D3",
                '" fill-opacity="',
                fid % 2 == 0 ? "1" : "0.5",
                '"'
            )
        );

        // Directly use the constructed attributes string in the SVG to minimize variables
        return
            string(
                abi.encodePacked(
                    '<svg width="1000" height="1000" viewBox="0 0 1000 1000" fill="none" xmlns="http://www.w3.org/2000/svg">',
                    '<rect width="1000" height="1000" rx="200" ',
                    attributes,
                    "/>",
                    '<path d="M257.778 155.556H742.222V844.444H671.111V528.889H670.414C662.554 441.677 589.258 373.333 500 373.333C410.742 373.333 337.446 441.677 329.586 528.889H328.889V844.444H257.778V155.556Z" fill="white" fill-opacity="',
                    fid % 2 == 0 ? "1" : "0.5",
                    '"/>',
                    '<path d="M128.889 253.333L157.778 351.111H182.222V746.667C169.949 746.667 160 756.616 160 768.889V795.556H155.556C143.283 795.556 133.333 805.505 133.333 817.778V844.444H382.222V817.778C382.222 805.505 372.273 795.556 360 795.556H355.556V768.889C355.556 756.616 345.606 746.667 333.333 746.667H306.667V253.333H128.889Z" fill="white" fill-opacity="',
                    fid % 2 == 0 ? "1" : "0.5",
                    '"/>',
                    '<path d="M675.556 746.667C663.283 746.667 653.333 756.616 653.333 768.889V795.556H648.889C636.616 795.556 626.667 805.505 626.667 817.778V844.444H875.556V817.778C875.556 805.505 865.606 795.556 853.333 795.556H848.889V768.889C848.889 756.616 838.94 746.667 826.667 746.667V351.111H851.111L880 253.333H702.222V746.667H675.556Z" fill="white" fill-opacity="',
                    fid % 2 == 0 ? "1" : "0.5",
                    '"/>',
                    '<text x="500" y="950" font-family="Arial" font-size="48" fill="white" text-anchor="middle">',
                    fid.toString(),
                    " / ",
                    tokenID.toString(),
                    "</text>",
                    "</svg>"
                )
            );
    }

    function buildTokenURI(
        uint256 tokenId,
        uint256 fid,
        bool claimed
    ) public pure returns (string memory) {
        string memory svg = generateSVG(fid, tokenId, claimed);
        string memory svgBase64 = encodeBase64(svg);

        // Directly construct and encode JSON metadata to minimize local variables
        return
            string(
                abi.encodePacked(
                    "data:application/json;base64,",
                    encodeBase64(
                        string(
                            abi.encodePacked(
                                '{"name": "FoldSpace NFT #',
                                tokenId.toString(),
                                '","description": "NFT for registering Farcast Ids","image": "data:image/svg+xml;base64,',
                                svgBase64,
                                '"}'
                            )
                        )
                    )
                )
            );
    }
}
