// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Vm} from "forge-std/Vm.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {console2 as console} from "forge-std/Test.sol";
import {TestUtils} from "./utils/TestUtils.sol";
import {FoldSpace} from "../src/FoldSpace.sol";
import {ProxyFid} from "../src/ProxyFid.sol";
import {FoldSpaceTokenURI} from "../src/FoldSpaceTokenURI.sol";
import {IBundler} from "../src/interfaces/IBundler.sol";

contract FoldSpaceTest is TestUtils {
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

    function testMintWithClaim(uint40 _deadline, uint256 _minterPk) public {
        uint256 minterPk = bound(_minterPk, 1, 255);
        address minter = vm.addr(minterPk);
        uint256 deadline = _boundDeadline(_deadline);
        uint256 fidRegistrationPrice = IBundler(BUNDLER).price(1);
        uint256 nextFid = idRegistry.idCounter() + 1;

        uint256 balanceBefore = 1 ether + fidRegistrationPrice;

        hoax(minter, balanceBefore);
        uint tokenId = foldSpace.mint{value: fidRegistrationPrice}();
        address proxyFid = foldSpace.getProxyFor(tokenId);
        uint256 fid = foldSpace.getFidFor(tokenId);
        uint256 overPayment = minter.balance - 1 ether;

        assertEq(foldSpace.ownerOf(tokenId), address(minter));
        assertNotEq(proxyFid, address(proxyTemplate));
        assertEq(tokenId, 1);
        assertEq(fid, nextFid);
        assertEq(idRegistry.idCounter(), fid);
        assertEq(idRegistry.custodyOf(fid), proxyFid);
        assertEq(idRegistry.idOf(proxyFid), fid);
        assertTrue(minter.balance < balanceBefore);
        assertTrue(overPayment < fidRegistrationPrice);
        assertFalse(foldSpace.claimed(tokenId));

        bytes memory transferSignature = _signTransfer(
            minterPk,
            fid,
            minter,
            deadline
        );

        hoax(minter);
        foldSpace.claimFid(tokenId, deadline, transferSignature);
        assertEq(idRegistry.custodyOf(nextFid), minter);
        assertEq(idRegistry.idOf(minter), fid);
        assertTrue(foldSpace.claimed(tokenId));
    }

    function testMintFor(
        uint40 _deadline,
        uint256 _minterPk,
        uint256 _recipientPk
    ) public {
        vm.assume(_minterPk != _recipientPk);
        uint256 minterPk = bound(_minterPk, 1, 255);
        uint256 recipientPk = bound(_recipientPk, 1, 255);
        uint256 deadline = _boundDeadline(_deadline);
        address recipient = vm.addr(recipientPk);
        uint256 fidRegistrationPrice = IBundler(BUNDLER).price(1);
        uint256 nextFid = idRegistry.idCounter() + 1;
        bytes memory signature;
        address minter = vm.addr(minterPk);

        uint256 balanceBefore = 1 ether + fidRegistrationPrice;

        hoax(minter, balanceBefore);
        uint tokenId = foldSpace.mintFor{value: fidRegistrationPrice}(
            recipient
        );
        uint256 fid;
        {
            address proxyFid = foldSpace.getProxyFor(tokenId);
            fid = foldSpace.getFidFor(tokenId);
            uint256 overPayment = minter.balance - 1 ether;

            assertTrue(proxyFid != address(0));
            assertEq(foldSpace.ownerOf(tokenId), address(recipient));
            assertNotEq(proxyFid, address(proxyTemplate));
            assertEq(tokenId, 1);
            assertEq(fid, nextFid);
            assertEq(idRegistry.idCounter(), fid);
            assertEq(idRegistry.custodyOf(fid), proxyFid);
            assertEq(idRegistry.idOf(proxyFid), fid);
            assertTrue(minter.balance < balanceBefore);
            assertTrue(overPayment < fidRegistrationPrice);
            assertFalse(foldSpace.claimed(tokenId));
        }

        bytes memory transferSignature = _signTransfer(
            recipientPk,
            fid,
            recipient,
            deadline
        );

        hoax(recipient);
        foldSpace.claimFid(tokenId, deadline, transferSignature);
        assertEq(idRegistry.custodyOf(nextFid), recipient);
        assertEq(idRegistry.idOf(recipient), fid);
        assertTrue(foldSpace.claimed(tokenId));
    }

    function testMintAndTransferForClaim(
        uint40 _deadline,
        uint256 _minterPk,
        uint256 _recipientPk
    ) public {
        vm.assume(_minterPk != _recipientPk);
        uint256 minterPk = bound(_minterPk, 1, 255);
        uint256 recipientPk = bound(_recipientPk, 1, 255);
        uint256 deadline = _boundDeadline(_deadline);
        address recipient = vm.addr(recipientPk);
        uint256 fidRegistrationPrice = IBundler(BUNDLER).price(1);
        uint256 nextFid = idRegistry.idCounter() + 1;
        bytes memory signature;
        address minter;
        uint tokenId;
        uint256 balanceBefore = 1 ether + fidRegistrationPrice;
        {
            minter = vm.addr(minterPk);
            // mint to minter
            hoax(minter, balanceBefore);
            tokenId = foldSpace.mint{value: fidRegistrationPrice}();
        }
        address proxyFid = foldSpace.getProxyFor(tokenId);
        uint256 fid = foldSpace.getFidFor(tokenId);
        uint256 overPayment = minter.balance - 1 ether;
        assertTrue(overPayment < fidRegistrationPrice);

        // minter gifts to recipient
        hoax(minter);
        foldSpace.transferFrom(minter, recipient, tokenId);

        assertTrue(proxyFid != address(0));
        assertEq(foldSpace.ownerOf(tokenId), address(recipient));
        assertNotEq(proxyFid, address(proxyTemplate));
        assertEq(tokenId, 1);
        assertEq(fid, nextFid);
        assertEq(idRegistry.idCounter(), fid);
        assertEq(idRegistry.custodyOf(fid), proxyFid);
        assertEq(idRegistry.idOf(proxyFid), fid);
        assertFalse(foldSpace.claimed(tokenId));

        // recipient can unwrap the fid
        bytes memory transferSignature = _signTransfer(
            recipientPk,
            fid,
            recipient,
            deadline
        );

        hoax(recipient);
        foldSpace.claimFid(tokenId, deadline, transferSignature);
        assertEq(idRegistry.custodyOf(nextFid), recipient);
        assertEq(idRegistry.idOf(recipient), fid);
        assertTrue(foldSpace.claimed(tokenId));
    }

    function testCanMintSeveralNfts(uint40 _deadline, uint256 _minting) public {
        uint256 minterPk = 0xACCE1;
        address minter = vm.addr(minterPk);
        uint256 deadline = _boundDeadline(_deadline);
        uint256 minting = bound(_minting, 2, 10);

        uint256 fidRegistrationPrice = IBundler(BUNDLER).price(1);

        uint256 balanceBefore = 1 ether + fidRegistrationPrice;
        deal(minter, balanceBefore);

        for (uint8 i = 0; i < minting; i++) {
            vm.prank(minter);
            uint tokenId = foldSpace.mint{value: fidRegistrationPrice}();
            address proxyFid = foldSpace.getProxyFor(tokenId);
            uint256 fid = foldSpace.getFidFor(tokenId);

            assertTrue(proxyFid != address(0));
            assertEq(foldSpace.ownerOf(tokenId), address(minter));
            assertNotEq(proxyFid, address(proxyTemplate));
            assertEq(idRegistry.idCounter(), fid);
            assertEq(idRegistry.custodyOf(fid), proxyFid);
            assertEq(idRegistry.idOf(proxyFid), fid);
            assertTrue(minter.balance < balanceBefore);
            assertFalse(foldSpace.claimed(tokenId));
        }

        assertEq(foldSpace.balanceOf(minter), minting);
    }

    function testFailWhenClaimingTwice(
        uint40 _deadline,
        uint256 _minterPk
    ) public {
        uint256 minterPk = bound(_minterPk, 1, 255);
        address minter = vm.addr(minterPk);
        uint256 deadline = _boundDeadline(_deadline);
        uint256 fidRegistrationPrice = IBundler(BUNDLER).price(1);
        uint256 nextFid = idRegistry.idCounter() + 1;

        uint256 balanceBefore = 1 ether + fidRegistrationPrice;

        hoax(minter, balanceBefore);
        uint tokenId = foldSpace.mint{value: fidRegistrationPrice}();
        uint256 fid = foldSpace.getFidFor(tokenId);

        bytes memory transferSignature = _signTransfer(
            minterPk,
            fid,
            minter,
            deadline
        );

        hoax(minter);
        foldSpace.claimFid(tokenId, deadline, transferSignature);
        assertEq(idRegistry.custodyOf(nextFid), minter);
        assertEq(idRegistry.idOf(minter), fid);
        assertTrue(foldSpace.claimed(tokenId));

        foldSpace.claimFid(tokenId, deadline, transferSignature);
    }

    function testFailCantClaimIfAlredyRegistered(
        uint40 _deadline,
        uint256 _minterPk
    ) public {
        uint256 minterPk = bound(_minterPk, 1, 255);
        address minter = vm.addr(minterPk);
        uint256 deadline = _boundDeadline(_deadline);
        uint256 fidRegistrationPrice = IBundler(BUNDLER).price(1);
        uint256 nextFid = idRegistry.idCounter() + 1;

        uint256 balanceBefore = 1 ether + fidRegistrationPrice;

        hoax(minter, balanceBefore);
        uint tokenId = foldSpace.mint{value: fidRegistrationPrice}();
        uint256 fid = foldSpace.getFidFor(tokenId);

        bytes memory transferSignature = _signTransfer(
            minterPk,
            fid,
            minter,
            deadline
        );
        // Claims first FID
        hoax(minter);
        foldSpace.claimFid(tokenId, deadline, transferSignature);
        assertEq(idRegistry.custodyOf(nextFid), minter);
        assertEq(idRegistry.idOf(minter), fid);
        assertTrue(foldSpace.claimed(tokenId));

        {
            address minter_ = minter;
            uint256 minterPk_ = minterPk;
            uint256 deadline_ = deadline;

            hoax(minter_, balanceBefore);
            uint secondTokenId = foldSpace.mint{value: fidRegistrationPrice}();
            uint256 secondFid = foldSpace.getFidFor(secondTokenId);

            bytes memory secondTransferSignature = _signTransfer(
                minterPk_,
                secondFid,
                minter_,
                deadline_
            );

            // Claims second FID should fail
            vm.expectRevert("FoldSpace: USER_ALREADY_HAS_FID");
            hoax(minter_);
            foldSpace.claimFid(tokenId, deadline_, secondTransferSignature);
        }
    }

    function testFailSendingETHToFoldSpace(uint256 _callerPk) public {
        uint256 callerPk = bound(_callerPk, 1, 255);

        address caller = vm.addr(callerPk);
        deal(caller, 2 ether);

        vm.prank(caller);
        payable(address(foldSpace)).transfer(1 ether);
    }
}
