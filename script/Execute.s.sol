// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm, VmSafe} from "forge-std/Vm.sol";
import {DryRunBase} from "./DryRunBase.sol";
import {ISafe, IMultiSend, ISafeMigration} from "../src/ISafe.sol";
import {SafeConstants as C} from "../src/SafeConstants.sol";

/// Phase 1: inspect the Safe, dissect the proposed upgrade transaction, simulate it while
/// recording every storage write, then (if it succeeds) replay it on the local Anvil fork.
///
/// Env: SAFE, RUN_DIR, TX_MODE ("file" reads RUN_DIR/tx.json, "reference" builds the canonical batch).
contract Execute is DryRunBase {
    struct Inner {
        uint8 op;
        address to;
        uint256 value;
        bytes data;
    }

    struct Write {
        address account;
        bytes32 slot;
        bytes32 prev;
        bytes32 next;
    }

    bytes32 private constant EV_EXECUTION_SUCCESS = keccak256("ExecutionSuccess(bytes32,uint256)");
    bytes32 private constant EV_EXECUTION_FAILURE = keccak256("ExecutionFailure(bytes32,uint256)");
    bytes32 private constant EV_CHANGED_MASTER_COPY = keccak256("ChangedMasterCopy(address)");
    bytes32 private constant EV_CHANGED_FALLBACK_HANDLER = keccak256("ChangedFallbackHandler(address)");

    function run() external {
        _init("execute");

        section("Safe before the upgrade");
        Snapshot memory before = _snapshot();
        info(string.concat("address          ", str(address(safe))));
        _printSnapshot(before);
        _writeSnapshot(before, "before");

        section("Preconditions");
        _preconditions(before);

        SafeTx memory t = _loadTx(before);

        section("Proposed transaction");
        _describeTx(t);

        section("What signers will see");
        bytes32 txHash = _hashes(t);

        bool executed;
        if (t.nonce != before.nonce) {
            section("Execution");
            fail(
                string.concat(
                    "transaction nonce is ",
                    str(t.nonce),
                    " but the Safe is at nonce ",
                    str(before.nonce),
                    t.nonce > before.nonce
                        ? ": earlier queued transactions must execute first, so this cannot be simulated yet"
                        : ": this nonce has already been used"
                )
            );
        } else {
            executed = _simulateAndBroadcast(t, txHash, before);
        }

        _finish("execute", executed);
    }

    // ---------------------------------------------------------- preconditions

    function _preconditions(Snapshot memory s) internal {
        check(
            s.singleton == C.SAFE_111 && keccak256(bytes(s.version)) == keccak256("1.1.1"),
            "Safe is on the canonical 1.1.1 singleton",
            string.concat("Safe is not on the canonical 1.1.1 singleton (slot 0 = ", str(s.singleton), ", VERSION = '", s.version, "')")
        );
        if (s.proxyCodehash == C.PROXY_111_CODEHASH) {
            pass("proxy bytecode is the standard 1.1.1 factory proxy");
        } else {
            warn(string.concat("proxy bytecode hash ", str(s.proxyCodehash), " is not the standard 1.1.1 factory proxy; check how this Safe was deployed"));
        }
        check(safe.masterCopy() == s.singleton, "proxy's masterCopy() agrees with storage slot 0");
        check(s.ownerCount == s.owners.length && s.threshold >= 1 && s.threshold <= s.owners.length, "owner count and threshold are consistent");
        check(
            s.legacyDomainSeparator == _legacyDomainSeparator() && safe.domainSeparator() == s.legacyDomainSeparator,
            "stored domain separator is the legacy (chain-id-less) one for this address"
        );
        check(
            s.guard == bytes32(0) && s.moduleGuard == bytes32(0),
            "guard and module-guard slots are empty (nothing dormant would wake up under 1.5.0)",
            "guard or module-guard slot is already non-zero: 1.1.1 ignores it, 1.5.0 would start enforcing it"
        );
        if (s.fallbackHandler == C.DEFAULT_CALLBACK_HANDLER_111) {
            pass("fallback handler is the stock DefaultCallbackHandler 1.1.1");
        } else if (s.fallbackHandler == address(0)) {
            warn("no fallback handler is set");
        } else {
            warn(string.concat("custom fallback handler ", str(s.fallbackHandler), ": the upgrade replaces it, check nothing depends on it"));
        }
        if (s.modules.length == 0) {
            pass("no modules enabled");
        } else {
            warn(string.concat(str(s.modules.length), " module(s) enabled: they keep full access after the upgrade; test each one against 1.5.0 separately"));
        }
        check(
            C.SAFE_150.code.length > 0 && keccak256(bytes(_version(C.SAFE_150))) == keccak256("1.5.0"),
            "target singleton has code and reports VERSION 1.5.0"
        );
        check(C.COMPAT_FALLBACK_HANDLER_150.code.length > 0, "target fallback handler has code");

        for (uint256 i; i < s.owners.length; i++) {
            _classifyOwner(s.owners[i]);
        }
    }

    function _classifyOwner(address o) internal {
        bytes memory code = o.code;
        if (code.length == 0) return;
        if (code.length == 23 && code[0] == 0xef && code[1] == 0x01 && code[2] == 0x00) {
            info(string.concat("owner ", str(o), " is an EOA with an EIP-7702 delegation; it still signs as an EOA"));
            return;
        }
        string memory v = _version(o);
        if (bytes(v).length == 0) {
            warn(string.concat("owner ", str(o), " is a contract (not a Safe): to co-sign under 1.5.0 it must implement isValidSignature(bytes32,bytes) or call approveHash"));
        } else if (bytes(v)[0] == "1" && bytes(v).length >= 3 && (bytes(v)[2] == "0" || bytes(v)[2] == "1" || bytes(v)[2] == "2")) {
            warn(string.concat("owner ", str(o), " is a Safe ", v, ": it only speaks legacy EIP-1271, so under 1.5.0 it can co-sign only via on-chain approveHash"));
        } else {
            info(string.concat("owner ", str(o), " is a Safe ", v, " (contract signatures go through its fallback handler)"));
        }
    }

    // ------------------------------------------------------------ transaction

    function _loadTx(Snapshot memory s) internal returns (SafeTx memory t) {
        string memory path = string.concat(runDir, "/tx.json");
        if (keccak256(bytes(vm.envString("TX_MODE"))) == keccak256("reference")) {
            t.to = C.MULTISEND_CALL_ONLY_130;
            t.operation = 1;
            t.nonce = s.nonce;
            t.data = abi.encodeCall(
                IMultiSend.multiSend,
                (
                    abi.encodePacked(
                        _packCall(address(safe), abi.encodeCall(ISafe.changeMasterCopy, (C.SAFE_150))),
                        _packCall(address(safe), abi.encodeCall(ISafe.setFallbackHandler, (C.COMPAT_FALLBACK_HANDLER_150)))
                    )
                )
            );
            string memory k = "tx";
            vm.serializeString(k, "origin", "reference transaction built by safe-dryrun");
            vm.serializeString(k, "to", str(t.to));
            vm.serializeString(k, "value", "0");
            vm.serializeString(k, "data", vm.toString(t.data));
            vm.serializeString(k, "operation", "1");
            vm.serializeString(k, "safeTxGas", "0");
            vm.serializeString(k, "baseGas", "0");
            vm.serializeString(k, "gasPrice", "0");
            vm.serializeString(k, "gasToken", str(address(0)));
            vm.serializeString(k, "refundReceiver", str(address(0)));
            vm.serializeString(k, "safeTxHash", "");
            vm.writeJson(vm.serializeString(k, "nonce", str(t.nonce)), path);
            return t;
        }
        string memory j = vm.readFile(path);
        t.to = vm.parseAddress(vm.parseJsonString(j, ".to"));
        t.value = vm.parseUint(vm.parseJsonString(j, ".value"));
        t.data = vm.parseBytes(vm.parseJsonString(j, ".data"));
        t.operation = uint8(vm.parseUint(vm.parseJsonString(j, ".operation")));
        t.safeTxGas = vm.parseUint(vm.parseJsonString(j, ".safeTxGas"));
        t.baseGas = vm.parseUint(vm.parseJsonString(j, ".baseGas"));
        t.gasPrice = vm.parseUint(vm.parseJsonString(j, ".gasPrice"));
        t.gasToken = vm.parseAddress(vm.parseJsonString(j, ".gasToken"));
        t.refundReceiver = vm.parseAddress(vm.parseJsonString(j, ".refundReceiver"));
        t.nonce = vm.parseUint(vm.parseJsonString(j, ".nonce"));
    }

    function _packCall(address to, bytes memory data) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, uint256(0), data.length, data);
    }

    function _describeTx(SafeTx memory t) internal {
        string memory j = vm.readFile(string.concat(runDir, "/tx.json"));
        info(string.concat("source           ", vm.parseJsonString(j, ".origin")));
        info(string.concat("to               ", named(t.to)));
        info(string.concat("operation        ", t.operation == 0 ? "0 (CALL)" : t.operation == 1 ? "1 (DELEGATECALL)" : str(uint256(t.operation))));
        info(string.concat("value            ", str(t.value)));
        info(string.concat("nonce            ", str(t.nonce)));
        info(string.concat("data             ", str(t.data.length), " bytes, keccak ", str(keccak256(t.data))));

        check(t.to.code.length > 0, "target has code");
        check(t.value == 0, "sends no ETH");
        if (t.gasPrice == 0 && t.gasToken == address(0) && t.refundReceiver == address(0)) {
            pass("no gas refund is requested");
        } else {
            warn("gas refund parameters are set (gasPrice / gasToken / refundReceiver): the Safe would pay someone for execution");
        }

        bytes4 sel = t.data.length >= 4 ? bytes4(t.data) : bytes4(0);

        if (t.operation == 1 && sel == IMultiSend.multiSend.selector && (C.isMultiSendCallOnly(t.to) || C.isMultiSend(t.to))) {
            (Inner[] memory inner, bool ok) = _decodeBatch(t.data);
            if (!ok) {
                fail("MultiSend payload is malformed and could not be decoded");
                return;
            }
            if (C.isMultiSendCallOnly(t.to)) {
                pass("batch goes through an official MultiSendCallOnly (inner delegatecalls are impossible)");
            } else {
                warn("batch goes through MultiSend rather than MultiSendCallOnly, which permits inner delegatecalls");
            }
            for (uint256 i; i < inner.length; i++) {
                info(string.concat("  call ", str(i + 1), ": ", _describeInner(inner[i])));
            }
            bool canonical = inner.length == 2
                && _isCall(inner[0], abi.encodeCall(ISafe.changeMasterCopy, (C.SAFE_150)))
                && _isCall(inner[1], abi.encodeCall(ISafe.setFallbackHandler, (C.COMPAT_FALLBACK_HANDLER_150)));
            check(
                canonical,
                "payload is exactly the canonical batch: changeMasterCopy(Safe 1.5.0) then setFallbackHandler(CompatibilityFallbackHandler 1.5.0)",
                "batch is NOT exactly [changeMasterCopy(Safe 1.5.0), setFallbackHandler(CompatibilityFallbackHandler 1.5.0)] on this Safe"
            );
        } else if (t.operation == 0 && t.to == address(safe) && keccak256(t.data) == keccak256(abi.encodeCall(ISafe.changeMasterCopy, (C.SAFE_150)))) {
            fail("payload only calls changeMasterCopy(Safe 1.5.0): the 1.1.1 fallback handler would stay, leaving the Safe without EIP-1271 and view helpers");
        } else if (t.operation == 1 && t.to == C.SAFE_MIGRATION_150 && t.data.length == 4) {
            if (sel == ISafeMigration.migrateWithFallbackHandler.selector) {
                warn("payload delegatecalls SafeMigration 1.5.0 migrateWithFallbackHandler(): mechanically fine, but not what the Safe UI builds for 1.1.1 and not a path Safe tests from 1.1.1");
            } else if (sel == ISafeMigration.migrateSingleton.selector) {
                fail("payload delegatecalls SafeMigration 1.5.0 migrateSingleton(): the 1.1.1 fallback handler would stay");
            } else {
                fail("payload delegatecalls SafeMigration 1.5.0 with an L2 or unknown selector: mainnet Safes should end on the L1 singleton");
            }
        } else {
            fail("payload is NOT a recognised Safe upgrade. Treat every state change below with suspicion.");
        }
    }

    function _isCall(Inner memory c, bytes memory data) private view returns (bool) {
        return c.op == 0 && c.to == address(safe) && c.value == 0 && keccak256(c.data) == keccak256(data);
    }

    function _describeInner(Inner memory c) private view returns (string memory out) {
        out = string.concat(c.op == 0 ? "CALL " : "DELEGATECALL ", named(c.to), " ");
        bytes4 sel = c.data.length >= 4 ? bytes4(c.data) : bytes4(0);
        if (c.data.length == 36 && (sel == ISafe.changeMasterCopy.selector || sel == ISafe.setFallbackHandler.selector)) {
            address arg = address(uint160(uint256(_word(c.data, 4))));
            out = string.concat(out, sel == ISafe.changeMasterCopy.selector ? "changeMasterCopy(" : "setFallbackHandler(", named(arg), ")");
        } else {
            out = string.concat(out, "data ", vm.toString(c.data));
        }
        if (c.value != 0) out = string.concat(out, " value ", str(c.value));
    }

    function _word(bytes memory b, uint256 offset) private pure returns (bytes32 w) {
        require(b.length >= offset + 32, "out of bounds");
        assembly {
            w := mload(add(add(b, 0x20), offset))
        }
    }

    /// External so a malformed ABI payload turns into a caught revert instead of aborting the run.
    function decodeBytesArg(bytes calldata data) external pure returns (bytes memory) {
        return abi.decode(data[4:], (bytes));
    }

    function _decodeBatch(bytes memory data) private view returns (Inner[] memory out, bool ok) {
        bytes memory packed;
        try this.decodeBytesArg(data) returns (bytes memory p) {
            packed = p;
        } catch {
            return (out, false);
        }
        Inner[] memory buf = new Inner[](64);
        uint256 n;
        uint256 i;
        while (i < packed.length) {
            if (packed.length < i + 85 || n == buf.length) return (out, false);
            Inner memory c;
            c.op = uint8(packed[i]);
            c.to = address(uint160(uint256(_word(packed, i + 1)) >> 96));
            c.value = uint256(_word(packed, i + 21));
            uint256 len = uint256(_word(packed, i + 53));
            if (len > packed.length || packed.length < i + 85 + len) return (out, false);
            c.data = new bytes(len);
            for (uint256 k; k < len; k++) {
                c.data[k] = packed[i + 85 + k];
            }
            buf[n++] = c;
            i += 85 + len;
        }
        out = new Inner[](n);
        for (uint256 k; k < n; k++) {
            out[k] = buf[k];
        }
        ok = true;
    }

    // ----------------------------------------------------------------- hashes

    function _hashes(SafeTx memory t) internal returns (bytes32 txHash) {
        bytes32 domain = _legacyDomainSeparator();
        bytes32 structHash = _structHash(t);
        txHash = _eip712(domain, structHash);
        info(string.concat("domain hash      ", str(domain)));
        info(string.concat("message hash     ", str(structHash)));
        info(string.concat("safeTxHash       ", str(txHash)));
        info("(EIP-712 domain is { verifyingContract } only: 1.1.1 does not bind signatures to a chain id)");
        check(_onchainHash(t) == txHash, "safeTxHash matches the Safe's own getTransactionHash()");

        string memory claimed = vm.parseJsonString(vm.readFile(string.concat(runDir, "/tx.json")), ".safeTxHash");
        if (bytes(claimed).length > 0) {
            check(
                vm.parseBytes32(claimed) == txHash,
                "safeTxHash matches the one reported by the Safe Transaction Service",
                string.concat("Safe Transaction Service reports a different safeTxHash: ", claimed)
            );
        }
    }

    // -------------------------------------------------------------- execution

    function _simulateAndBroadcast(SafeTx memory t, bytes32 txHash, Snapshot memory before) internal returns (bool) {
        address[] memory signers = _pickSigners(before.owners, before.threshold);
        bytes memory callData = _execCalldata(t, _approvedSignatures(signers));

        // Rehearse off to the side first, recording everything the transaction touches.
        uint256 snap = vm.snapshotState();
        for (uint256 i = 1; i < signers.length; i++) {
            vm.prank(signers[i]);
            safe.approveHash(txHash);
        }
        vm.recordLogs();
        vm.startStateDiffRecording();
        vm.prank(signers[0]);
        (bool ok, bytes memory ret) = address(safe).call(callData);
        Vm.AccountAccess[] memory accesses = vm.stopAndReturnStateDiff();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        vm.revertToState(snap);

        section("Execution");
        info(string.concat("executor         ", str(signers[0]), " (impersonated owner)"));
        for (uint256 i = 1; i < signers.length; i++) {
            info(string.concat("approveHash by   ", str(signers[i]), " (impersonated owner)"));
        }
        if (!ok) {
            fail(string.concat("execTransaction reverted: ", _revertReason(ret)));
            return false;
        }
        bool innerOk = _events(logs);
        if (!innerOk) {
            fail("the inner call failed. Under 1.1.1 this does not revert: on mainnet it would burn the nonce and change nothing else");
            return false;
        }
        pass("execTransaction succeeds with threshold owner approvals");

        section("Code that ran");
        _codeThatRan(accesses, t);

        section("Storage written");
        _storageWritten(accesses, txHash, signers, before);

        // Now do it for real on the local fork.
        for (uint256 i = 1; i < signers.length; i++) {
            vm.broadcast(signers[i]);
            safe.approveHash(txHash);
        }
        vm.broadcast(signers[0]);
        (ok,) = address(safe).call(callData);
        require(ok, "execTransaction succeeded in rehearsal but reverted on replay");
        return true;
    }

    function _events(Vm.Log[] memory logs) internal returns (bool innerOk) {
        bool success;
        bool failure;
        bool masterCopy;
        bool handler;
        for (uint256 i; i < logs.length; i++) {
            Vm.Log memory l = logs[i];
            bytes32 t0 = l.topics.length > 0 ? l.topics[0] : bytes32(0);
            if (l.emitter != address(safe)) {
                warn(string.concat("event emitted by another contract: ", named(l.emitter), " topic0 ", str(t0)));
            } else if (t0 == EV_EXECUTION_SUCCESS) {
                success = true;
            } else if (t0 == EV_EXECUTION_FAILURE) {
                failure = true;
            } else if (t0 == EV_CHANGED_MASTER_COPY) {
                masterCopy = abi.decode(l.data, (address)) == C.SAFE_150;
            } else if (t0 == EV_CHANGED_FALLBACK_HANDLER) {
                // 1.5.0 indexes the handler; older code put it in data.
                address h = l.topics.length > 1 ? address(uint160(uint256(l.topics[1]))) : abi.decode(l.data, (address));
                handler = h == C.COMPAT_FALLBACK_HANDLER_150;
            } else {
                warn(string.concat("unexpected event from the Safe, topic0 ", str(t0)));
            }
        }
        innerOk = success && !failure;
        if (innerOk) {
            check(masterCopy, "emits ChangedMasterCopy(Safe 1.5.0)");
            check(handler, "emits ChangedFallbackHandler(CompatibilityFallbackHandler 1.5.0)");
        }
    }

    function _codeThatRan(Vm.AccountAccess[] memory acc, SafeTx memory t) internal {
        address[] memory seen = new address[](acc.length);
        uint256 n;
        bool clean = true;
        for (uint256 i; i < acc.length; i++) {
            Vm.AccountAccess memory a = acc[i];
            if (a.reverted) continue;
            VmSafe.AccountAccessKind k = a.kind;
            if (k == VmSafe.AccountAccessKind.Create || k == VmSafe.AccountAccessKind.SelfDestruct) {
                fail(string.concat("contract creation or self-destruct at ", str(a.account)));
                clean = false;
                continue;
            }
            if (
                k != VmSafe.AccountAccessKind.Call && k != VmSafe.AccountAccessKind.DelegateCall
                    && k != VmSafe.AccountAccessKind.StaticCall && k != VmSafe.AccountAccessKind.CallCode
            ) continue;
            if (a.value != 0) {
                fail(string.concat("ETH moved: ", str(a.value), " wei to ", str(a.account)));
                clean = false;
            }
            bool dup;
            for (uint256 j; j < n; j++) {
                if (seen[j] == a.account) dup = true;
            }
            if (dup) continue;
            seen[n++] = a.account;
            bool expected = a.account == address(safe) || a.account == C.SAFE_111 || a.account == C.SAFE_150
                || (a.account == t.to && (C.isMultiSendCallOnly(t.to) || C.isMultiSend(t.to)));
            if (expected) {
                info(named(a.account));
            } else {
                fail(string.concat("unexpected contract executed: ", named(a.account)));
                clean = false;
            }
        }
        if (clean) pass("only the Safe, its old and new singletons and the MultiSend contract executed; no ETH moved");
    }

    function _storageWritten(Vm.AccountAccess[] memory acc, bytes32 txHash, address[] memory signers, Snapshot memory before) internal {
        Write[] memory w = _netWrites(acc);
        bool sawSingleton;
        bool sawNonce;
        bool sawHandler;
        bool clean = true;

        bytes32[] memory slots = new bytes32[](w.length);
        bytes32[] memory nexts = new bytes32[](w.length);
        address[] memory accounts = new address[](w.length);

        for (uint256 i; i < w.length; i++) {
            slots[i] = w[i].slot;
            nexts[i] = w[i].next;
            accounts[i] = w[i].account;
            string memory change = string.concat(str(w[i].prev), " -> ", str(w[i].next));

            if (w[i].account != address(safe)) {
                fail(string.concat("storage of another contract changed: ", named(w[i].account), " slot ", str(w[i].slot), ": ", change));
                clean = false;
            } else if (w[i].slot == bytes32(C.SLOT_SINGLETON)) {
                sawSingleton = true;
                info(string.concat("slot 0 (singleton): ", str(_asAddr(w[i].prev)), " -> ", named(_asAddr(w[i].next))));
                if (_asAddr(w[i].prev) != C.SAFE_111 || w[i].next != bytes32(uint256(uint160(C.SAFE_150)))) {
                    fail("singleton slot does not go from Safe 1.1.1 to exactly Safe 1.5.0");
                    clean = false;
                }
            } else if (w[i].slot == bytes32(C.SLOT_NONCE)) {
                sawNonce = true;
                info(string.concat("slot 5 (nonce): ", str(uint256(w[i].prev)), " -> ", str(uint256(w[i].next))));
                if (uint256(w[i].prev) != before.nonce || uint256(w[i].next) != before.nonce + 1) {
                    fail("nonce does not advance by exactly one");
                    clean = false;
                }
            } else if (w[i].slot == C.SLOT_FALLBACK_HANDLER) {
                sawHandler = true;
                info(string.concat("fallback handler slot: ", str(_asAddr(w[i].prev)), " -> ", named(_asAddr(w[i].next))));
                if (w[i].next != bytes32(uint256(uint160(C.COMPAT_FALLBACK_HANDLER_150)))) {
                    fail("fallback handler does not end as CompatibilityFallbackHandler 1.5.0");
                    clean = false;
                }
            } else if (_isApprovalSlot(w[i].slot, txHash, signers) && w[i].next == bytes32(0)) {
                info("approvedHashes[owner][safeTxHash]: 1 -> 0 (simulation artefact: an on-chain approval being consumed)");
            } else {
                fail(string.concat("unexpected storage write: ", _slotName(w[i].slot, before), " ", str(w[i].slot), ": ", change));
                clean = false;
            }
        }
        if (!sawSingleton) fail("singleton slot was not written");
        if (!sawNonce) fail("nonce slot was not written");
        if (!sawHandler) fail("fallback handler slot was not written");
        if (clean && sawSingleton && sawNonce && sawHandler) {
            pass("the only lasting changes are singleton, fallback handler and nonce");
        }

        string memory k = "statediff";
        vm.serializeAddress(k, "accounts", accounts);
        vm.serializeBytes32(k, "slots", slots);
        vm.serializeBytes32(k, "safeTxHash", txHash);
        vm.writeJson(vm.serializeBytes32(k, "values", nexts), string.concat(runDir, "/statediff.json"));
    }

    /// Collapses the access list into one entry per (account, slot): first old value, last new value.
    function _netWrites(Vm.AccountAccess[] memory acc) private pure returns (Write[] memory out) {
        uint256 total;
        for (uint256 i; i < acc.length; i++) {
            total += acc[i].storageAccesses.length;
        }
        Write[] memory buf = new Write[](total);
        uint256 n;
        for (uint256 i; i < acc.length; i++) {
            for (uint256 j; j < acc[i].storageAccesses.length; j++) {
                Vm.StorageAccess memory sa = acc[i].storageAccesses[j];
                if (!sa.isWrite || sa.reverted) continue;
                uint256 at = n;
                for (uint256 x; x < n; x++) {
                    if (buf[x].account == sa.account && buf[x].slot == sa.slot) at = x;
                }
                if (at == n) buf[n++] = Write(sa.account, sa.slot, sa.previousValue, sa.newValue);
                else buf[at].next = sa.newValue;
            }
        }
        uint256 changed;
        for (uint256 i; i < n; i++) {
            if (buf[i].prev != buf[i].next) changed++;
        }
        out = new Write[](changed);
        uint256 o;
        for (uint256 i; i < n; i++) {
            if (buf[i].prev != buf[i].next) out[o++] = buf[i];
        }
    }

    function _asAddr(bytes32 v) private pure returns (address) {
        return address(uint160(uint256(v)));
    }

    function _isApprovalSlot(bytes32 slot, bytes32 txHash, address[] memory signers) private pure returns (bool) {
        for (uint256 i; i < signers.length; i++) {
            if (slot == keccak256(abi.encode(txHash, keccak256(abi.encode(signers[i], C.SLOT_APPROVED_HASHES))))) return true;
        }
        return false;
    }

    function _slotName(bytes32 slot, Snapshot memory s) private pure returns (string memory) {
        if (slot == bytes32(C.SLOT_OWNER_COUNT)) return "ownerCount";
        if (slot == bytes32(C.SLOT_THRESHOLD)) return "threshold";
        if (slot == bytes32(C.SLOT_LEGACY_DOMAIN_SEPARATOR)) return "legacy domain separator";
        if (slot == C.SLOT_GUARD) return "transaction guard";
        if (slot == C.SLOT_MODULE_GUARD) return "module guard";
        if (slot == keccak256(abi.encode(C.SENTINEL, C.SLOT_OWNERS))) return "owners list head";
        if (slot == keccak256(abi.encode(C.SENTINEL, C.SLOT_MODULES))) return "modules list head";
        for (uint256 i; i < s.owners.length; i++) {
            if (slot == keccak256(abi.encode(s.owners[i], C.SLOT_OWNERS))) return "owners list entry";
        }
        for (uint256 i; i < s.modules.length; i++) {
            if (slot == keccak256(abi.encode(s.modules[i], C.SLOT_MODULES))) return "modules list entry";
        }
        return "unrecognised slot";
    }
}
