// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Union of the Safe 1.1.1 and 1.5.0 surfaces this tool touches. Not every function exists in
/// every version; callers know which side of the upgrade they are on.
interface ISafe {
    // --- both versions ---
    function VERSION() external view returns (string memory);
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function isOwner(address owner) external view returns (bool);
    function nonce() external view returns (uint256);
    function domainSeparator() external view returns (bytes32);
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);
    function approveHash(bytes32 hashToApprove) external;
    function approvedHashes(address owner, bytes32 hash) external view returns (uint256);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) external payable returns (bool success);
    function addOwnerWithThreshold(address owner, uint256 _threshold) external;
    function removeOwner(address prevOwner, address owner, uint256 _threshold) external;
    function enableModule(address module) external;
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success);
    function setFallbackHandler(address handler) external;

    // --- 1.1.1 only ---
    function changeMasterCopy(address _masterCopy) external;

    // --- 1.5.0 only ---
    function isModuleEnabled(address module) external view returns (bool);

    // --- answered by the proxy itself ---
    function masterCopy() external view returns (address);

    // --- answered by the 1.5.0 CompatibilityFallbackHandler through the Safe's fallback ---
    function getModules() external view returns (address[] memory);
    function getMessageHash(bytes calldata message) external view returns (bytes32);
    function isValidSignature(bytes32 dataHash, bytes calldata signature) external view returns (bytes4);
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4);
}

interface IMultiSend {
    function multiSend(bytes calldata transactions) external payable;
}

interface ISafeMigration {
    function migrateSingleton() external;
    function migrateWithFallbackHandler() external;
    function migrateL2Singleton() external;
    function migrateL2WithFallbackHandler() external;
}
