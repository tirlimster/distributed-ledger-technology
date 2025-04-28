// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

/// @title  PoetryNFT – publish poems & receive an NFT
contract PoetryNFT is ERC721URIStorage {
    uint256 private _nextTokenId;              // <-- plain counter

    mapping(uint256 => string) public poemText;

    event PoemPublished(address indexed author, uint256 indexed tokenId, string text);

    constructor() ERC721("Poetry Collection", "POEM") {}

    /// Publish a poem and mint an NFT to the sender
    function publish(string calldata text) external returns (uint256 tokenId) {
        tokenId = ++_nextTokenId;              // increment safely (Solidity ≥0.8)
        string memory uri = _buildTokenURI(tokenId, text);

        _mint(msg.sender, tokenId);
        _setTokenURI(tokenId, uri);

        poemText[tokenId] = text;
        emit PoemPublished(msg.sender, tokenId, text);
    }

    /* ---------- internal helpers ---------- */

    function _buildTokenURI(uint256 id, string calldata text) private pure returns (string memory) {
        // Tiny, self-contained JSON metadata
        string memory json = string(
            abi.encodePacked('{"name":"Poem #', _uint2str(id), '","description":"', text, '"}')
        );
        return string(abi.encodePacked("data:application/json;utf8,", json));
    }

    // Very small uint-to-string, avoids importing Strings.sol
    function _uint2str(uint256 value) private pure returns (string memory str) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + value % 10));
            value /= 10;
        }
        str = string(buffer);
    }
}
