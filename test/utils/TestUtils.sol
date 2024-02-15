// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {IIdRegistry} from "../../src/interfaces/IIdRegistry.sol";
import {IIdGateway} from "../../src/interfaces/IIdGateway.sol";
import {IBundler} from "../../src/interfaces/IBundler.sol";

abstract contract TestUtils is Test {
    uint256 constant SECP_256K1_ORDER =
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    address public constant ID_REGISTRY =
        0x00000000Fc6c5F01Fc30151999387Bb99A9f489b;
    address public constant ID_GATEWAY =
        0x00000000Fc25870C6eD6b6c7E41Fb078b7656f69;
    address public constant BUNDLER =
        0x00000000FC04c910A0b5feA33b03E0447AD0B0aA;

    // Contracts to exclude from fuzzing
    address[] internal knownContracts = [
        address(ID_REGISTRY), // ID_REGISTRY
        address(ID_GATEWAY), // ID_GATEWAY
        address(BUNDLER), // BUNDLER
        address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D), // Vm cheatcode address
        address(0x000000000000000000636F6e736F6c652e6c6f67) // console.sol
    ];

    IIdGateway idGateway;
    IIdRegistry public idRegistry;

    // Address of known contracts, in a mapping for faster lookup when fuzzing
    mapping(address => bool) isKnownContract;

    address owner = makeAddr("owner");

    function setUp() public virtual {
        // Set up the known contracts map
        for (uint256 i = 0; i < knownContracts.length; i++) {
            isKnownContract[knownContracts[i]] = true;
        }
        idRegistry = IIdRegistry(ID_REGISTRY);
        idGateway = IIdGateway(ID_GATEWAY);
    }

    function addKnownContract(address contractAddress) public {
        isKnownContract[contractAddress] = true;
    }

    // Ensures that a fuzzed address input does not match a known contract address
    function _assumeClean(address a) internal {
        // assumeNoPrecompiles(a);
        vm.assume(!isKnownContract[a]);
        vm.assume(a != address(0));
    }

    function _boundPk(uint256 pk) internal pure returns (uint256) {
        return bound(pk, 1, SECP_256K1_ORDER - 1);
    }

    function _boundDeadline(uint40 deadline) internal view returns (uint256) {
        return block.timestamp + uint256(bound(deadline, 0, type(uint40).max));
    }

    function _signRegister(
        uint256 pk,
        address to,
        address recovery,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        address signer = vm.addr(pk);
        bytes32 digest = idGateway.hashTypedDataV4(
            keccak256(
                abi.encode(
                    idGateway.REGISTER_TYPEHASH(),
                    to,
                    recovery,
                    idGateway.nonces(signer),
                    deadline
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        signature = abi.encodePacked(r, s, v);
        assertEq(signature.length, 65);
    }

    function _signTransfer(
        uint256 pk,
        uint256 fid,
        address to,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        address signer = vm.addr(pk);
        bytes32 digest = idRegistry.hashTypedDataV4(
            keccak256(
                abi.encode(
                    idRegistry.TRANSFER_TYPEHASH(),
                    fid,
                    to,
                    idRegistry.nonces(signer),
                    deadline
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        signature = abi.encodePacked(r, s, v);
        assertEq(signature.length, 65);
    }
}
