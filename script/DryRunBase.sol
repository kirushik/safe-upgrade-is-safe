// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {ISafe} from "../src/ISafe.sol";
import {SafeConstants as C} from "../src/SafeConstants.sol";

/// Shared plumbing for the two dry-run phases: report output, Safe state snapshots,
/// EIP-712 hashing and the "owners approve on-chain" signature scheme.
abstract contract DryRunBase is Script {
    /// The fork must never look like mainnet to a wallet; the wrapper starts Anvil with this id.
    uint256 internal constant FORK_CHAIN_ID = 31337;
    uint256 internal constant MAINNET_CHAIN_ID = 1;

    struct SafeTx {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address refundReceiver;
        uint256 nonce;
    }

    struct Snapshot {
        address singleton;
        string version;
        address[] owners;
        uint256 ownerCount;
        uint256 threshold;
        uint256 nonce;
        address[] modules;
        address fallbackHandler;
        bytes32 guard;
        bytes32 moduleGuard;
        bytes32 legacyDomainSeparator;
        uint256 balance;
        bytes32 proxyCodehash;
    }

    ISafe internal safe;
    string internal runDir;
    string private reportPath;
    uint256 internal passes;
    uint256 internal warns;
    uint256 internal fails;

    // ------------------------------------------------------------------ setup

    function _init(string memory phase) internal {
        require(
            block.chainid == FORK_CHAIN_ID,
            "refusing to run: chain id is not the local fork's (31337). This tool only ever talks to its own Anvil."
        );
        safe = ISafe(vm.envAddress("SAFE"));
        runDir = vm.envString("RUN_DIR");
        reportPath = string.concat(runDir, "/report-", phase, ".txt");
        if (vm.exists(reportPath)) vm.removeFile(reportPath);
    }

    function _finish(string memory phase, bool executed) internal {
        string memory k = string.concat("summary-", phase);
        vm.serializeUint(k, "passes", passes);
        vm.serializeUint(k, "warns", warns);
        vm.serializeUint(k, "fails", fails);
        vm.writeJson(vm.serializeBool(k, "executed", executed), string.concat(runDir, "/summary-", phase, ".json"));
    }

    // ----------------------------------------------------------------- report

    function line(string memory s) internal {
        console2.log(s);
        vm.writeLine(reportPath, s);
    }

    function section(string memory title) internal {
        line("");
        line(string.concat("== ", title, " =="));
    }

    function info(string memory m) internal {
        line(string.concat("         ", m));
    }

    function pass(string memory m) internal {
        passes++;
        line(string.concat("  [ ok ] ", m));
    }

    function warn(string memory m) internal {
        warns++;
        line(string.concat("  [WARN] ", m));
    }

    function fail(string memory m) internal {
        fails++;
        line(string.concat("  [FAIL] ", m));
    }

    function check(bool cond, string memory m) internal {
        if (cond) pass(m);
        else fail(m);
    }

    function check(bool cond, string memory okMsg, string memory failMsg) internal {
        if (cond) pass(okMsg);
        else fail(failMsg);
    }

    function str(address a) internal pure returns (string memory) {
        return vm.toString(a);
    }

    function str(uint256 a) internal pure returns (string memory) {
        return vm.toString(a);
    }

    function str(bytes32 a) internal pure returns (string memory) {
        return vm.toString(a);
    }

    /// Address plus a human name when it is a known canonical contract.
    function named(address a) internal view returns (string memory) {
        string memory n = _name(a);
        return bytes(n).length == 0 ? str(a) : string.concat(str(a), " (", n, ")");
    }

    function _name(address a) internal view returns (string memory) {
        if (a == address(safe)) return "this Safe";
        if (a == C.SAFE_111) return "Safe 1.1.1 singleton";
        if (a == C.SAFE_150) return "Safe 1.5.0 singleton";
        if (a == C.SAFE_L2_150) return "SafeL2 1.5.0 singleton";
        if (a == C.DEFAULT_CALLBACK_HANDLER_111) return "DefaultCallbackHandler 1.1.1";
        if (a == C.COMPAT_FALLBACK_HANDLER_150) return "CompatibilityFallbackHandler 1.5.0";
        if (a == C.SAFE_MIGRATION_150) return "SafeMigration 1.5.0";
        if (a == C.MULTISEND_CALL_ONLY_130) return "MultiSendCallOnly 1.3.0";
        if (a == C.MULTISEND_CALL_ONLY_130_EIP155) return "MultiSendCallOnly 1.3.0 eip155";
        if (a == C.MULTISEND_CALL_ONLY_141) return "MultiSendCallOnly 1.4.1";
        if (a == C.MULTISEND_CALL_ONLY_150) return "MultiSendCallOnly 1.5.0";
        if (a == C.MULTISEND_111) return "MultiSend 1.1.1";
        if (a == C.MULTISEND_130) return "MultiSend 1.3.0";
        if (a == C.MULTISEND_130_EIP155) return "MultiSend 1.3.0 eip155";
        if (a == C.MULTISEND_141) return "MultiSend 1.4.1";
        if (a == C.MULTISEND_150) return "MultiSend 1.5.0";
        return "";
    }

    // --------------------------------------------------------------- snapshot

    function _slotAddr(bytes32 slot) internal view returns (address) {
        return address(uint160(uint256(vm.load(address(safe), slot))));
    }

    function _version(address a) internal view returns (string memory) {
        if (a.code.length == 0) return "";
        try ISafe(a).VERSION() returns (string memory v) {
            return v;
        } catch {
            return "";
        }
    }

    /// Walks the modules linked list straight from storage, so it works identically before and
    /// after the upgrade (the getter's pagination semantics changed between versions).
    function _modules() internal view returns (address[] memory out) {
        address[] memory buf = new address[](256);
        uint256 n;
        address cur = _slotAddr(keccak256(abi.encode(C.SENTINEL, C.SLOT_MODULES)));
        while (cur != address(0) && cur != C.SENTINEL && n < buf.length) {
            buf[n++] = cur;
            cur = _slotAddr(keccak256(abi.encode(cur, C.SLOT_MODULES)));
        }
        out = new address[](n);
        for (uint256 i; i < n; i++) {
            out[i] = buf[i];
        }
    }

    function _snapshot() internal view returns (Snapshot memory s) {
        address a = address(safe);
        s.singleton = _slotAddr(bytes32(C.SLOT_SINGLETON));
        s.version = _version(a);
        s.owners = safe.getOwners();
        s.ownerCount = uint256(vm.load(a, bytes32(C.SLOT_OWNER_COUNT)));
        s.threshold = uint256(vm.load(a, bytes32(C.SLOT_THRESHOLD)));
        s.nonce = uint256(vm.load(a, bytes32(C.SLOT_NONCE)));
        s.modules = _modules();
        s.fallbackHandler = _slotAddr(C.SLOT_FALLBACK_HANDLER);
        s.guard = vm.load(a, C.SLOT_GUARD);
        s.moduleGuard = vm.load(a, C.SLOT_MODULE_GUARD);
        s.legacyDomainSeparator = vm.load(a, bytes32(C.SLOT_LEGACY_DOMAIN_SEPARATOR));
        s.balance = a.balance;
        s.proxyCodehash = a.codehash;
    }

    function _printSnapshot(Snapshot memory s) internal {
        info(string.concat("singleton        ", named(s.singleton)));
        info(string.concat("VERSION()        ", s.version));
        info(string.concat("threshold        ", str(s.threshold), " of ", str(s.owners.length)));
        for (uint256 i; i < s.owners.length; i++) {
            info(string.concat("  owner          ", str(s.owners[i])));
        }
        info(string.concat("nonce            ", str(s.nonce)));
        info(string.concat("fallback handler ", named(s.fallbackHandler)));
        info(string.concat("modules          ", str(s.modules.length)));
        for (uint256 i; i < s.modules.length; i++) {
            info(string.concat("  module         ", str(s.modules[i])));
        }
        info(string.concat("ETH balance      ", str(s.balance), " wei"));
    }

    function _writeSnapshot(Snapshot memory s, string memory name) internal {
        string memory k = name;
        vm.serializeAddress(k, "singleton", s.singleton);
        vm.serializeString(k, "version", s.version);
        vm.serializeAddress(k, "owners", s.owners);
        vm.serializeUint(k, "ownerCount", s.ownerCount);
        vm.serializeUint(k, "threshold", s.threshold);
        vm.serializeUint(k, "nonce", s.nonce);
        vm.serializeAddress(k, "modules", s.modules);
        vm.serializeUint(k, "moduleCount", s.modules.length);
        vm.serializeAddress(k, "fallbackHandler", s.fallbackHandler);
        vm.serializeBytes32(k, "guard", s.guard);
        vm.serializeBytes32(k, "moduleGuard", s.moduleGuard);
        vm.serializeBytes32(k, "legacyDomainSeparator", s.legacyDomainSeparator);
        vm.serializeString(k, "balance", str(s.balance));
        vm.writeJson(vm.serializeBytes32(k, "proxyCodehash", s.proxyCodehash), string.concat(runDir, "/", name, ".json"));
    }

    function _readSnapshot(string memory name) internal view returns (Snapshot memory s) {
        string memory j = vm.readFile(string.concat(runDir, "/", name, ".json"));
        s.singleton = vm.parseJsonAddress(j, ".singleton");
        s.version = vm.parseJsonString(j, ".version");
        s.owners = vm.parseJsonAddressArray(j, ".owners");
        s.ownerCount = vm.parseJsonUint(j, ".ownerCount");
        s.threshold = vm.parseJsonUint(j, ".threshold");
        s.nonce = vm.parseJsonUint(j, ".nonce");
        if (vm.parseJsonUint(j, ".moduleCount") > 0) s.modules = vm.parseJsonAddressArray(j, ".modules");
        s.fallbackHandler = vm.parseJsonAddress(j, ".fallbackHandler");
        s.guard = vm.parseJsonBytes32(j, ".guard");
        s.moduleGuard = vm.parseJsonBytes32(j, ".moduleGuard");
        s.legacyDomainSeparator = vm.parseJsonBytes32(j, ".legacyDomainSeparator");
        s.balance = vm.parseUint(vm.parseJsonString(j, ".balance"));
        s.proxyCodehash = vm.parseJsonBytes32(j, ".proxyCodehash");
    }

    function _sameAddresses(address[] memory a, address[] memory b) internal pure returns (bool) {
        return keccak256(abi.encode(a)) == keccak256(abi.encode(b));
    }

    // ---------------------------------------------------------------- hashing

    function _legacyDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(C.LEGACY_DOMAIN_TYPEHASH, address(safe)));
    }

    function _domainSeparator(uint256 chainId) internal view returns (bytes32) {
        return keccak256(abi.encode(C.DOMAIN_TYPEHASH, chainId, address(safe)));
    }

    function _structHash(SafeTx memory t) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                C.SAFE_TX_TYPEHASH,
                t.to,
                t.value,
                keccak256(t.data),
                t.operation,
                t.safeTxGas,
                t.baseGas,
                t.gasPrice,
                t.gasToken,
                t.refundReceiver,
                t.nonce
            )
        );
    }

    function _eip712(bytes32 domain, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domain, structHash));
    }

    function _onchainHash(SafeTx memory t) internal view returns (bytes32) {
        return safe.getTransactionHash(
            t.to, t.value, t.data, t.operation, t.safeTxGas, t.baseGas, t.gasPrice, t.gasToken, t.refundReceiver, t.nonce
        );
    }

    // ---------------------------------------------------------------- signers

    /// The lowest-addressed `threshold` owners, ascending (the order checkSignatures demands).
    /// signers[0] sends execTransaction; the rest approve the hash on-chain beforehand.
    function _pickSigners(address[] memory owners, uint256 threshold) internal pure returns (address[] memory s) {
        address[] memory o = new address[](owners.length);
        for (uint256 i; i < owners.length; i++) {
            o[i] = owners[i];
        }
        for (uint256 i = 1; i < o.length; i++) {
            address x = o[i];
            uint256 j = i;
            while (j > 0 && o[j - 1] > x) {
                o[j] = o[j - 1];
                j--;
            }
            o[j] = x;
        }
        require(threshold > 0 && threshold <= o.length, "bad threshold");
        s = new address[](threshold);
        for (uint256 i; i < threshold; i++) {
            s[i] = o[i];
        }
    }

    /// "Pre-validated" signatures (v = 1): valid for an owner that is msg.sender or has called
    /// approveHash. No private key is involved anywhere.
    function _approvedSignatures(address[] memory signers) internal pure returns (bytes memory sigs) {
        for (uint256 i; i < signers.length; i++) {
            sigs = abi.encodePacked(sigs, bytes32(uint256(uint160(signers[i]))), bytes32(0), uint8(1));
        }
    }

    function _execCalldata(SafeTx memory t, bytes memory sigs) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ISafe.execTransaction,
            (
                t.to,
                t.value,
                t.data,
                t.operation,
                t.safeTxGas,
                t.baseGas,
                t.gasPrice,
                t.gasToken,
                payable(t.refundReceiver),
                sigs
            )
        );
    }

    function _revertReason(bytes memory ret) internal pure returns (string memory) {
        if (ret.length >= 68 && bytes4(ret) == 0x08c379a0) {
            bytes memory payload = new bytes(ret.length - 4);
            for (uint256 i; i < payload.length; i++) {
                payload[i] = ret[i + 4];
            }
            return abi.decode(payload, (string));
        }
        return ret.length == 0 ? "(no revert data)" : vm.toString(ret);
    }
}
