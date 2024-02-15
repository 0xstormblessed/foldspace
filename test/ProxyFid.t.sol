// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Vm} from "forge-std/Vm.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {console2 as console} from "forge-std/Test.sol";
import {Initializable} from "@openzeppelin/proxy/utils/Initializable.sol";
import {TestUtils} from "./utils/TestUtils.sol";
import {FoldSpace} from "../src/FoldSpace.sol";
import {ProxyFid} from "../src/ProxyFid.sol";
import {FoldSpaceTokenURI} from "../src/FoldSpaceTokenURI.sol";
import {IBundler} from "../src/interfaces/IBundler.sol";
import {TransferHelper} from "../src/libraries/TransferHelper.sol";

contract ProxyFidTest is TestUtils {
    using TransferHelper for address;

    uint256 constant OP_FORK_BLOCK = 115881379;

    uint256 public mainnetForkId;
    ProxyFid public proxyTemplate;
    FoldSpace public foldSpace;
    FoldSpaceTokenURI public tokenURIGenerator;

    function setUp() public override {
        super.setUp();

        mainnetForkId = vm.createSelectFork(
            vm.rpcUrl("optimism"),
            OP_FORK_BLOCK
        );
        tokenURIGenerator = new FoldSpaceTokenURI();
        foldSpace = new FoldSpace(owner, address(tokenURIGenerator));
        proxyTemplate = foldSpace.PROXY_TEMPLATE();
        addKnownContract(address(foldSpace));
        addKnownContract(address(proxyTemplate));

        vm.label(address(idRegistry), "registry");
        vm.label(address(idGateway), "idGateway");
        vm.label(address(foldSpace), "foldspace");
        vm.label(address(proxyTemplate), "proxyTemplate");
    }

    function testSetup() public {
        assertEq(
            idRegistry.idOf(
                address(0x8773442740C17C9d0F0B87022c722F9a136206eD)
            ),
            1
        );
        assertEq(
            idRegistry.custodyOf(1),
            address(0x8773442740C17C9d0F0B87022c722F9a136206eD)
        );
        assertEq(idRegistry.idCounter(), 321203);
        assertEq(foldSpace.owner(), owner);
        assertTrue(address(foldSpace.PROXY_TEMPLATE()) != address(0));
        assertEq(proxyTemplate.FOLD_SPACE(), address(foldSpace));
        assertEq(proxyTemplate.isOriginal(), true);
        assertEq(foldSpace.counter(), 0);
    }

    function testFailCantInitializeProxyFidTemplate(
        uint40 _fid,
        uint256 _ownerId
    ) public {
        proxyTemplate.initialize(_ownerId, _fid, address(foldSpace));
    }

    function testFailCantCallCloneOnProxyFid(
        uint8 _fid,
        uint8 _ownerId,
        uint8 _callerPk
    ) public {
        address caller = vm.addr(_callerPk);
        vm.prank(caller);
        proxyTemplate.clone(_ownerId, caller);
    }

    function testCannotCallClaimFidOnProxyFid(
        uint40 _deadline,
        uint256 _minterPk,
        uint256 _callerPk
    ) public {
        uint256 callerPk = bound(_callerPk, 1, 255);
        uint256 minterPk = bound(_minterPk, 1, 255);
        address minter = vm.addr(minterPk);
        address caller = vm.addr(callerPk);
        uint256 deadline = _boundDeadline(_deadline);
        uint256 fidRegistrationPrice = IBundler(BUNDLER).price(1);

        bytes memory signature = _signRegister(
            minterPk,
            minter,
            address(0),
            deadline
        );

        uint256 balanceBefore = 1 ether + fidRegistrationPrice;

        hoax(minter, balanceBefore);
        uint tokenId = foldSpace.mint{value: fidRegistrationPrice}();
        address proxyFid = foldSpace.getProxyFor(tokenId);

        vm.expectRevert("ProxyFid: FORBIDDEN");
        vm.prank(caller);
        ProxyFid(payable(proxyFid)).claimFid(caller, deadline, signature);
    }

    function testCannotInitializeTwiceAProxyFid(
        uint40 _deadline,
        uint256 _minterPk,
        uint256 _callerPk
    ) public {
        uint256 callerPk = bound(_callerPk, 1, 255);
        uint256 minterPk = bound(_minterPk, 1, 255);
        address minter = vm.addr(minterPk);
        address caller = vm.addr(callerPk);
        uint256 deadline = _boundDeadline(_deadline);
        uint256 fidRegistrationPrice = IBundler(BUNDLER).price(1);

        bytes memory signature = _signRegister(
            minterPk,
            minter,
            address(0),
            deadline
        );

        uint256 balanceBefore = 1 ether + fidRegistrationPrice;

        hoax(minter, balanceBefore);
        uint tokenId = foldSpace.mint{value: fidRegistrationPrice}();
        address proxyFid = foldSpace.getProxyFor(tokenId);
        uint diffTokenId = tokenId + 1;

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        vm.prank(caller);
        ProxyFid(payable(proxyFid)).initialize(
            diffTokenId,
            1,
            address(foldSpace)
        );
    }

    function testFailSendingETHToProxyID(uint256 _callerPk) public {
        uint256 callerPk = bound(_callerPk, 1, 255);

        address caller = vm.addr(callerPk);
        deal(caller, 2 ether);

        vm.prank(caller);
        payable(address(proxyTemplate)).transfer(1 ether);
    }
}
