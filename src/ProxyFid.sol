// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {Initializable} from "@openzeppelin/proxy/utils/Initializable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";
import {IIdRegistry} from "./interfaces/IIdRegistry.sol";
import {IIdGateway} from "./interfaces/IIdGateway.sol";
import {TransferHelper} from "./libraries/TransferHelper.sol";

/// @notice ProxyFid is a contract that registers and owns a Farcaster Id governed by the FoldSpace NFT contract.
/// @notice Compatible with ID_REGISTRY Version 2023.11.15;
/// @author storming0x

contract ProxyFid is Initializable, IERC1271 {
    using TransferHelper for address;

    bool public isOriginal;
    bool public claimed;
    address public foldSpace;
    // token id of NFT owner
    uint256 public ownerId;
    uint256 public fid;

    address public immutable FOLD_SPACE;
    address constant ID_REGISTRY = 0x00000000Fc6c5F01Fc30151999387Bb99A9f489b;
    address constant ID_GATEWAY = 0x00000000Fc25870C6eD6b6c7E41Fb078b7656f69;

    constructor() {
        FOLD_SPACE = msg.sender;
        isOriginal = true;
        _disableInitializers();
    }

    function initialize(
        uint256 _ownerId,
        uint256 _fid,
        address _foldspace
    )
        public
        payable
        initializer
        returns (uint256 mintedFid, uint256 overPayment)
    {
        ownerId = _ownerId;
        fid = _fid;
        foldSpace = _foldspace;

        // @dev claimer needs to later setup recovery address
        (mintedFid, overPayment) = IIdGateway(ID_GATEWAY).register{
            value: msg.value
        }(address(0));

        if (overPayment > 0) _foldspace.sendNative(overPayment);
    }

    function claimFid(
        address _recipient,
        uint256 _deadline,
        bytes calldata _signature
    ) external {
        require(msg.sender == foldSpace, "ProxyFid: FORBIDDEN");
        require(!claimed, "ProxyFid: ALREADY_CLAIMED");
        claimed = true;
        IIdRegistry(ID_REGISTRY).transfer(_recipient, _deadline, _signature);
    }

    function clone(
        uint256 _ownerId,
        address _sender
    ) public returns (address newProxyFid) {
        require(isOriginal, "ProxyFid: FORBIDDEN");
        require(msg.sender == FOLD_SPACE, "ProxyFid: FORBIDDEN");
        newProxyFid = _deploy(_ownerId, _sender);
    }

    function owner() public view returns (address) {
        return IERC721(payable(foldSpace)).ownerOf(ownerId);
    }

    function computeAddress(
        uint256 _salt,
        address _sender
    ) public view returns (address) {
        bytes32 salt = _getSalt(_salt, _sender, FOLD_SPACE);
        return
            Create2.computeAddress(
                keccak256(abi.encodePacked(salt)),
                keccak256(_getContractCreationCode(address(this))),
                address(this)
            );
    }

    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) public view returns (bytes4 magicValue) {
        return
            SignatureChecker.isValidSignatureNow(owner(), hash, signature)
                ? this.isValidSignature.selector
                : bytes4(0);
    }

    function _getSalt(
        uint256 _salt,
        address _sender,
        address _foldSpace
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_salt, _sender, _foldSpace));
    }

    function _getContractCreationCode(
        address logic
    ) internal pure returns (bytes memory) {
        bytes10 creation = 0x3d602d80600a3d3981f3;
        bytes10 prefix = 0x363d3d373d3d3d363d73;
        bytes20 targetBytes = bytes20(logic);
        bytes15 suffix = 0x5af43d82803e903d91602b57fd5bf3;
        return abi.encodePacked(creation, prefix, targetBytes, suffix);
    }

    function _deploy(
        uint256 _salt,
        address _sender
    ) internal returns (address) {
        bytes32 salt = _getSalt(_salt, _sender, FOLD_SPACE);
        address minimalProxy = Create2.deploy(
            0,
            keccak256(abi.encodePacked(salt)),
            _getContractCreationCode(address(this))
        );
        return minimalProxy;
    }

    receive() external payable {
        if (ID_GATEWAY != msg.sender) {
            revert("!authorized");
        }
    }
}
