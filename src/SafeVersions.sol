// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SafeConstants as C} from "./SafeConstants.sol";

/// What the tool knows about each Safe version: which singletons identify it, how an upgrade
/// away from it is performed, and what an upgrade to it should leave behind.
library SafeVersions {
    struct Source {
        bool known;
        string version;
        /// Pre-1.3.0: upgrades through changeMasterCopy and signs over a domain without chain id.
        bool legacy;
        bool l2;
    }

    struct Target {
        string version;
        address singleton;
        address singletonL2;
        address handler;
        /// SafeMigration contract for this version; zero when none exists (1.3.0).
        address migration;
        address multiSendCallOnly;
    }

    function source(address singleton) internal pure returns (Source memory) {
        if (singleton == C.SAFE_111) return Source(true, "1.1.1", true, false);
        if (singleton == C.SAFE_120) return Source(true, "1.2.0", true, false);
        if (singleton == C.SAFE_130 || singleton == C.SAFE_130_EIP155) return Source(true, "1.3.0", false, false);
        if (singleton == C.SAFE_L2_130 || singleton == C.SAFE_L2_130_EIP155) return Source(true, "1.3.0", false, true);
        if (singleton == C.SAFE_141) return Source(true, "1.4.1", false, false);
        if (singleton == C.SAFE_L2_141) return Source(true, "1.4.1", false, true);
        if (singleton == C.SAFE_150) return Source(true, "1.5.0", false, false);
        if (singleton == C.SAFE_L2_150) return Source(true, "1.5.0", false, true);
        return Source(false, "", false, false);
    }

    function target(string memory version) internal pure returns (Target memory) {
        bytes32 v = keccak256(bytes(version));
        if (v == keccak256("1.3.0")) {
            return Target(version, C.SAFE_130, C.SAFE_L2_130, C.COMPAT_FALLBACK_HANDLER_130, address(0), C.MULTISEND_CALL_ONLY_130);
        }
        if (v == keccak256("1.4.1")) {
            return Target(
                version, C.SAFE_141, C.SAFE_L2_141, C.COMPAT_FALLBACK_HANDLER_141, C.SAFE_MIGRATION_141, C.MULTISEND_CALL_ONLY_141
            );
        }
        if (v == keccak256("1.5.0")) {
            return Target(
                version, C.SAFE_150, C.SAFE_L2_150, C.COMPAT_FALLBACK_HANDLER_150, C.SAFE_MIGRATION_150, C.MULTISEND_CALL_ONLY_150
            );
        }
        revert("unsupported target version (use 1.3.0, 1.4.1 or 1.5.0)");
    }

    /// The stock fallback handler(s) the Safe UI deploys with a given version.
    function isStockHandler(string memory version, address handler) internal pure returns (bool) {
        if (bytes(version).length != 5) return false;
        uint256 r = rank(version);
        if (r < 130) return handler == C.DEFAULT_CALLBACK_HANDLER_111;
        if (r == 130) return handler == C.COMPAT_FALLBACK_HANDLER_130 || handler == C.COMPAT_FALLBACK_HANDLER_130_EIP155;
        if (r == 141) return handler == C.COMPAT_FALLBACK_HANDLER_141;
        return handler == C.COMPAT_FALLBACK_HANDLER_150;
    }

    /// "1.4.1" -> 141, for ordering.
    function rank(string memory version) internal pure returns (uint256) {
        bytes memory b = bytes(version);
        require(b.length == 5, "version must look like 1.5.0");
        return (uint8(b[0]) - 48) * 100 + (uint8(b[2]) - 48) * 10 + (uint8(b[4]) - 48);
    }

    function isKnownProxy(bytes32 codehash) internal pure returns (bool) {
        return codehash == C.PROXY_111_CODEHASH || codehash == C.PROXY_130_CODEHASH || codehash == C.PROXY_141_CODEHASH
            || codehash == C.PROXY_150_CODEHASH;
    }
}
