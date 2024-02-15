// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {FoldSpace} from "../src/FoldSpace.sol";
import {FoldSpaceTokenURI} from "../src/FoldSpaceTokenURI.sol";

contract DeployFoldSpace is Script {
    function run() public {
        vm.startBroadcast();
        FoldSpace foldSpace = new FoldSpace(
            msg.sender,
            address(new FoldSpaceTokenURI())
        );
        vm.stopBroadcast();
        console.log("FoldSpace deployed at", address(foldSpace));
    }
}
