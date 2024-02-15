// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**


      ___         ___                        _____          ___           ___         ___           ___           ___              
     /  /\       /  /\                      /  /::\        /  /\         /  /\       /  /\         /  /\         /  /\             
    /  /:/_     /  /::\                    /  /:/\:\      /  /:/_       /  /::\     /  /::\       /  /:/        /  /:/_            
   /  /:/ /\   /  /:/\:\    ___     ___   /  /:/  \:\    /  /:/ /\     /  /:/\:\   /  /:/\:\     /  /:/        /  /:/ /\           
  /  /:/ /:/  /  /:/  \:\  /__/\   /  /\ /__/:/ \__\:|  /  /:/ /::\   /  /:/~/:/  /  /:/~/::\   /  /:/  ___   /  /:/ /:/_          
 /__/:/ /:/  /__/:/ \__\:\ \  \:\ /  /:/ \  \:\ /  /:/ /__/:/ /:/\:\ /__/:/ /:/  /__/:/ /:/\:\ /__/:/  /  /\ /__/:/ /:/ /\         
 \  \:\/:/   \  \:\ /  /:/  \  \:\  /:/   \  \:\  /:/  \  \:\/:/~/:/ \  \:\/:/   \  \:\/:/__\/ \  \:\ /  /:/ \  \:\/:/ /:/         
  \  \::/     \  \:\  /:/    \  \:\/:/     \  \:\/:/    \  \::/ /:/   \  \::/     \  \::/       \  \:\  /:/   \  \::/ /:/          
   \  \:\      \  \:\/:/      \  \::/       \  \::/      \__\/ /:/     \  \:\      \  \:\        \  \:\/:/     \  \:\/:/           
    \  \:\      \  \::/        \__\/         \__\/         /__/:/       \  \:\      \  \:\        \  \::/       \  \::/            
     \__\/       \__\/                                     \__\/         \__\/       \__\/         \__\/         \__\/             

 */

import "@openzeppelin/token/ERC721/extensions/IERC721Enumerable.sol";
import "@openzeppelin/token/ERC721/extensions/ERC721Enumerable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ProxyFid} from "./ProxyFid.sol";
import {TransferHelper} from "./libraries/TransferHelper.sol";
import {ITokenURIGenerator} from "./interfaces/ITokenURIGenerator.sol";
import {IIdGateway} from "./interfaces/IIdGateway.sol";
import {IIdRegistry} from "./interfaces/IIdRegistry.sol";

/// @notice FoldSpace is an NFT contract for registering Farcaster Ids.
/// @notice Minting a FoldSpace NFT registers a Farcaster Id that you can claim or gift.
/// @notice Compatible with IdGateway Version 2023.11.15;
/// @author storming0x

contract FoldSpace is IERC721Enumerable, ERC721Enumerable, Ownable {
    using TransferHelper for address;

    address constant ID_REGISTRY = 0x00000000Fc6c5F01Fc30151999387Bb99A9f489b;
    address constant ID_GATEWAY = 0x00000000Fc25870C6eD6b6c7E41Fb078b7656f69;

    ProxyFid public immutable PROXY_TEMPLATE;
    address public tokenURIGenerator;
    uint256 public counter;

    mapping(uint256 => address) tokenIdToproxies;
    mapping(uint256 => uint256) public tokenIdToFid;
    mapping(uint256 => bool) public claimed;

    address temporarySender;

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _owner,
        address _tokenURIGenerator
    ) ERC721("FoldSpace", "FoldSpace") Ownable(_owner) {
        require(_tokenURIGenerator != address(0), "!tokenURIGenerator");

        PROXY_TEMPLATE = new ProxyFid();
        tokenURIGenerator = _tokenURIGenerator;
    }

    /*//////////////////////////////////////////////////////////////
                        PERMISSIONED FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setTokenURIGenerator(address _tokenURIGenerator) public onlyOwner {
        require(_tokenURIGenerator != address(0), "!tokenURIGenerator");
        tokenURIGenerator = _tokenURIGenerator;
    }

    /*//////////////////////////////////////////////////////////////
                        PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function mint() public payable returns (uint256 _tokenId) {
        _tokenId = _mintFor(msg.sender);
    }

    function mintFor(
        address _recipient
    ) public payable returns (uint256 _tokenId) {
        _tokenId = _mintFor(_recipient);
    }

    function claimFid(
        uint256 _tokenId,
        uint256 _deadline,
        bytes calldata _signature
    ) public {
        _claimFid(_tokenId, msg.sender, _deadline, _signature);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function getProxyFor(uint256 _tokenId) public view returns (address) {
        return tokenIdToproxies[_tokenId];
    }

    function getFidFor(uint256 _tokenId) public view returns (uint256) {
        return tokenIdToFid[_tokenId];
    }

    /**
     * @notice Calculate the total price to register in idGateway, equal to 1 storage unit.
     *
     * @return Total price in wei.
     */
    function price() public view returns (uint256) {
        return IIdGateway(ID_GATEWAY).price();
    }

    function tokenURI(uint256 id) public view override returns (string memory) {
        require(id != 0);
        require(id <= counter, "!exists");
        return
            ITokenURIGenerator(tokenURIGenerator).buildTokenURI(
                id,
                tokenIdToFid[id],
                claimed[id]
            );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _mintFor(address _to) internal returns (uint256) {
        // get the price of a registration in wei
        uint256 fidRegistrationPrice = IIdGateway(ID_GATEWAY).price();
        // check the msg.value has the correct amount
        require(msg.value >= fidRegistrationPrice, "FoldSpace: INVALID_AMOUNT");

        // get the next available fid
        IIdRegistry registry = IIdRegistry(ID_REGISTRY);
        uint256 nextFid = registry.idCounter() + 1;
        uint256 tokenId = counter + 1;
        // clone a new ProxyFid
        ProxyFid proxyFid = ProxyFid(
            payable(PROXY_TEMPLATE.clone(tokenId, msg.sender))
        );

        // HACK: temporary mint to the msg.sender so signature check works in idGateway via proxyFid
        _mint(msg.sender, tokenId);

        // in case proxyFid needs to send back overpayment
        temporarySender = address(proxyFid);

        // initialize and register an Fid
        (uint256 mintedFid, uint256 overpayment) = proxyFid.initialize{
            value: msg.value
        }(tokenId, nextFid, address(this));

        // disable temporarySender
        temporarySender = address(0);

        require(mintedFid == nextFid, "FoldSpace: UNEXPECTED_FID");

        // if the recipient is not the msg.sender, mint token to the recipient
        if (_to != msg.sender) {
            // burn the temporary mint
            _burn(tokenId);

            // finally mint to correct recipient
            _mint(_to, tokenId);
        }

        // record storage changes
        tokenIdToproxies[tokenId] = address(proxyFid);
        tokenIdToFid[tokenId] = mintedFid;
        unchecked {
            counter++;
        }

        // return leftover wei to the msg.sender
        if (overpayment > 0) msg.sender.sendNative(overpayment);

        return tokenId;
    }

    function _claimFid(
        uint256 _tokenId,
        address _recipient,
        uint256 _deadline,
        bytes calldata _signature
    ) internal {
        require(ownerOf(_tokenId) == msg.sender, "FoldSpace: NOT_OWNER");
        require(!claimed[_tokenId], "FoldSpace: ALREADY_CLAIMED");
        require(
            IIdRegistry(ID_REGISTRY).idOf(_recipient) == 0,
            "FoldSpace: USER_ALREADY_HAS_FID"
        );

        // transfer fid to _recipient in registry;
        address proxyFid = tokenIdToproxies[_tokenId];
        ProxyFid(payable(proxyFid)).claimFid(_recipient, _deadline, _signature);

        // mark the tokenId as claimed
        claimed[_tokenId] = true;
    }

    receive() external payable {
        if (temporarySender != msg.sender) {
            revert("!authorized");
        }
    }
}
