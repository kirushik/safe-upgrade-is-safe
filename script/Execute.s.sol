// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm, VmSafe} from "forge-std/Vm.sol";
import {DryRunBase} from "./DryRunBase.sol";
import {ISafe, IMultiSend, ISafeMigration} from "../src/ISafe.sol";
import {SafeConstants as C} from "../src/SafeConstants.sol";
import {SafeVersions as V} from "../src/SafeVersions.sol";

/// Phase 1: inspect the Safe, dissect the proposed upgrade transaction, simulate it while
/// recording every storage write, then (if it succeeds) replay it on the local Anvil fork.
///
/// Env: SAFE, RUN_DIR, TX_MODE ("file" reads RUN_DIR/tx.json, "reference" builds the transaction
/// the Safe UI is expected to propose), TARGET, TARGET_L2, FULL, TOKENS.
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
    // Extra bookkeeping event of the L2 singletons.
    bytes32 private constant EV_SAFE_MULTISIG_TRANSACTION = keccak256(
        "SafeMultiSigTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes,bytes)"
    );

    V.Source private src;
    /// What the proposed payload should leave behind, decided while dissecting it.
    address private expSingleton;
    address private expHandler;
    bool private setsHandler;

    function run() external {
        _init("execute");

        section("Safe before the upgrade");
        Snapshot memory before = _snapshot();
        info(string.concat("address          ", str(address(safe))));
        _printSnapshot(before);
        _writeSnapshot(before, "before");
        src = V.source(before.singleton);
        expSingleton = _targetSingleton();
        expHandler = tgt.handler;
        setsHandler = true;

        section("Preconditions");
        _preconditions(before);

        SafeTx memory t = _loadTx(before);

        section("Proposed transaction");
        _describeTx(t, before);
        _writeExpectations();

        section("What signers will see");
        bytes32 txHash = _hashes(t);

        signers = _pickSigners(before.owners, before.threshold);
        if (full) _tokenBaseline();

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

    function _writeExpectations() internal {
        string memory k = "expected";
        vm.serializeAddress(k, "singleton", expSingleton);
        vm.serializeAddress(k, "handler", expHandler);
        vm.serializeString(k, "sourceVersion", src.version);
        vm.writeJson(vm.serializeBool(k, "legacySource", src.legacy), string.concat(runDir, "/expected.json"));
    }

    // ---------------------------------------------------------- preconditions

    function _preconditions(Snapshot memory s) internal {
        string memory variant = src.l2 ? "SafeL2 " : "Safe ";
        if (src.known && keccak256(bytes(s.version)) == keccak256(bytes(src.version))) {
            pass(string.concat("Safe is on a canonical ", variant, src.version, " singleton"));
        } else {
            fail(string.concat("Safe is not on a singleton this tool knows (slot 0 = ", str(s.singleton), ", VERSION = '", s.version, "')"));
        }
        if (src.known) {
            check(
                V.rank(src.version) < V.rank(tgt.version),
                string.concat("upgrade direction is ", src.version, " -> ", tgt.version),
                string.concat("Safe is already on ", src.version, ", which is not older than the target ", tgt.version)
            );
            if (keccak256(bytes(src.version)) == keccak256("1.2.0")) {
                warn("1.2.0 Safes behave like 1.1.1 on paper, but this tool has not been run against a real one: read this report with extra care");
            }
            if (src.l2 && !wantL2) {
                info("this Safe runs the L2 singleton; the upgrade moves it to the L1 variant, as the Safe UI does on mainnet");
            }
        }
        if (V.isKnownProxy(s.proxyCodehash)) {
            pass("proxy bytecode is a standard Safe factory proxy");
        } else {
            warn(string.concat("proxy bytecode hash ", str(s.proxyCodehash), " is not a standard Safe factory proxy; check how this Safe was deployed"));
        }
        check(safe.masterCopy() == s.singleton, "proxy's masterCopy() agrees with storage slot 0");
        check(s.ownerCount == s.owners.length && s.threshold >= 1 && s.threshold <= s.owners.length, "owner count and threshold are consistent");

        if (src.legacy) {
            check(
                s.legacyDomainSeparator == _legacyDomainSeparator() && safe.domainSeparator() == s.legacyDomainSeparator,
                "stored domain separator is the legacy (chain-id-less) one for this address"
            );
            check(
                s.guard == bytes32(0),
                "guard slot is empty (nothing dormant would wake up after the upgrade)",
                "guard slot is already non-zero: this version ignores it, the new one would start enforcing it"
            );
        } else {
            check(safe.domainSeparator() == _domainSeparator(block.chainid), "domain separator is derived from the chain id");
            if (s.guard != bytes32(0)) {
                warn(string.concat("transaction guard ", str(address(uint160(uint256(s.guard)))), " is set: it stays in force and is consulted during the upgrade itself"));
            } else {
                pass("no transaction guard is set");
            }
        }
        if (s.moduleGuard != bytes32(0)) {
            if (V.rank(tgt.version) >= 150) fail("module-guard slot is already non-zero: 1.5.0 would start enforcing it");
            else warn("module-guard slot is non-zero; versions before 1.5.0 ignore it");
        }

        if (V.isStockHandler(src.version, s.fallbackHandler)) {
            pass(string.concat("fallback handler is the stock one for ", src.version));
        } else if (s.fallbackHandler == address(0)) {
            warn("no fallback handler is set");
        } else {
            warn(string.concat("custom fallback handler ", str(s.fallbackHandler), ": check what the upgrade does with it below"));
        }
        if (s.modules.length == 0) {
            pass("no modules enabled");
        } else {
            warn(string.concat(str(s.modules.length), " module(s) enabled: they keep full access after the upgrade; test each one against ", tgt.version, " separately"));
        }
        check(
            expSingleton.code.length > 0 && keccak256(bytes(_version(expSingleton))) == keccak256(bytes(tgt.version)),
            string.concat("target singleton has code and reports VERSION ", tgt.version)
        );
        check(tgt.handler.code.length > 0, "target fallback handler has code");

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
        bool newStyle = V.rank(tgt.version) >= 150;
        string memory v = _version(o);
        if (bytes(v).length != 5) {
            warn(
                string.concat(
                    "owner ",
                    str(o),
                    " is a contract (not a Safe): to co-sign under ",
                    tgt.version,
                    " it must implement ",
                    newStyle ? "isValidSignature(bytes32,bytes)" : "isValidSignature(bytes,bytes)",
                    " or call approveHash"
                )
            );
        } else if (V.rank(v) < 130 && newStyle) {
            warn(string.concat("owner ", str(o), " is a Safe ", v, ": it only speaks legacy EIP-1271, so under 1.5.0 it can co-sign only via on-chain approveHash"));
        } else {
            info(string.concat("owner ", str(o), " is a Safe ", v));
        }
    }

    // ------------------------------------------------------------ transaction

    function _loadTx(Snapshot memory s) internal returns (SafeTx memory t) {
        string memory path = string.concat(runDir, "/tx.json");
        if (keccak256(bytes(vm.envString("TX_MODE"))) == keccak256("reference")) {
            t.nonce = s.nonce;
            t.operation = 1;
            if (src.legacy || !src.known) {
                // Pre-1.3.0: the Safe UI batches changeMasterCopy and setFallbackHandler.
                t.to = C.MULTISEND_CALL_ONLY_130;
                t.data = abi.encodeCall(
                    IMultiSend.multiSend,
                    (
                        abi.encodePacked(
                            _packCall(address(safe), abi.encodeCall(ISafe.changeMasterCopy, (_targetSingleton()))),
                            _packCall(address(safe), abi.encodeCall(ISafe.setFallbackHandler, (tgt.handler)))
                        )
                    )
                );
            } else {
                // 1.3.0+: the Safe UI delegatecalls SafeMigration, and only moves the fallback
                // handler along when the current one is the stock handler.
                t.to = tgt.migration;
                bool stock = V.isStockHandler(src.version, s.fallbackHandler);
                t.data = abi.encodeWithSelector(
                    wantL2
                        ? (stock ? ISafeMigration.migrateL2WithFallbackHandler.selector : ISafeMigration.migrateL2Singleton.selector)
                        : (stock ? ISafeMigration.migrateWithFallbackHandler.selector : ISafeMigration.migrateSingleton.selector)
                );
            }
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

    function _describeTx(SafeTx memory t, Snapshot memory before) internal {
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
        bool isMigration = t.operation == 1 && t.data.length == 4 && (t.to == C.SAFE_MIGRATION_141 || t.to == C.SAFE_MIGRATION_150);

        if (isMigration) {
            _describeMigration(t, sel, before);
        } else if (!src.legacy) {
            fail(string.concat("payload is NOT the SafeMigration delegatecall the Safe UI uses to upgrade a ", src.version, " Safe. Treat every state change below with suspicion."));
        } else if (t.operation == 1 && sel == IMultiSend.multiSend.selector && (C.isMultiSendCallOnly(t.to) || C.isMultiSend(t.to))) {
            _describeBatch(t);
        } else if (t.operation == 0 && t.to == address(safe) && keccak256(t.data) == keccak256(abi.encodeCall(ISafe.changeMasterCopy, (expSingleton)))) {
            setsHandler = false;
            expHandler = before.fallbackHandler;
            fail("payload only calls changeMasterCopy: the old fallback handler would stay, leaving the Safe without EIP-1271 and view helpers");
        } else {
            fail("payload is NOT a recognised Safe upgrade. Treat every state change below with suspicion.");
        }
    }

    function _describeBatch(SafeTx memory t) private {
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
        bool canonical = inner.length == 2 && _isCall(inner[0], abi.encodeCall(ISafe.changeMasterCopy, (expSingleton)))
            && _isCall(inner[1], abi.encodeCall(ISafe.setFallbackHandler, (expHandler)));
        string memory want = string.concat("changeMasterCopy(", _name(expSingleton), ") then setFallbackHandler(", _name(expHandler), ")");
        if (canonical) {
            pass(string.concat("payload is exactly the canonical batch: ", want));
        } else {
            fail(string.concat("batch is NOT exactly: ", want, " on this Safe"));
            address other = wantL2 ? tgt.singleton : tgt.singletonL2;
            if (inner.length > 0 && _isCall(inner[0], abi.encodeCall(ISafe.changeMasterCopy, (other)))) {
                info(wantL2 ? "it moves to the L1 singleton although --l2 was given" : "it moves to the L2 singleton; pass --l2 if that is intended");
            }
        }
    }

    function _describeMigration(SafeTx memory t, bytes4 sel, Snapshot memory before) private {
        if (t.to != tgt.migration) {
            fail(string.concat("payload delegatecalls ", _name(t.to), ", which is not the migration contract for the target ", tgt.version));
            return;
        }
        bool withHandler = sel == ISafeMigration.migrateWithFallbackHandler.selector
            || sel == ISafeMigration.migrateL2WithFallbackHandler.selector;
        bool toL2 = sel == ISafeMigration.migrateL2Singleton.selector || sel == ISafeMigration.migrateL2WithFallbackHandler.selector;
        if (!withHandler && !toL2 && sel != ISafeMigration.migrateSingleton.selector) {
            fail(string.concat("payload delegatecalls ", _name(t.to), " with an unknown selector"));
            return;
        }
        string memory fn = toL2
            ? (withHandler ? "migrateL2WithFallbackHandler()" : "migrateL2Singleton()")
            : (withHandler ? "migrateWithFallbackHandler()" : "migrateSingleton()");
        info(string.concat("decoded          DELEGATECALL ", _name(t.to), " ", fn));
        setsHandler = withHandler;
        expHandler = withHandler ? tgt.handler : before.fallbackHandler;

        if (toL2 != wantL2) {
            fail(toL2 ? "payload moves to the L2 singleton; pass --l2 if that is intended" : "payload moves to the L1 singleton although --l2 was given");
            return;
        }
        if (src.legacy) {
            if (withHandler) {
                warn("payload uses SafeMigration from a pre-1.3.0 Safe: mechanically fine, but not what the Safe UI builds for it and not a path Safe tests");
            } else {
                fail("payload migrates only the singleton: the old fallback handler would stay, leaving the Safe without EIP-1271 and view helpers");
            }
            return;
        }
        pass(string.concat("payload is the SafeMigration ", tgt.version, " delegatecall the Safe UI uses: ", fn));
        bool stock = V.isStockHandler(src.version, before.fallbackHandler);
        if (withHandler && !stock && before.fallbackHandler != address(0)) {
            warn("it replaces a custom fallback handler; the Safe UI would have kept it");
        } else if (!withHandler && stock) {
            warn(string.concat("it keeps the ", src.version, " fallback handler; the Safe UI would have moved to the ", tgt.version, " one"));
        } else if (!withHandler) {
            info("the current fallback handler is kept, as the Safe UI does for non-stock handlers");
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

    /// Prints the hashes as mainnet signers will see them and returns the hash valid on the fork.
    function _hashes(SafeTx memory t) internal returns (bytes32 forkHash) {
        bytes32 structHash = _structHash(t);
        bytes32 mainnetDomain = src.legacy ? _legacyDomainSeparator() : _domainSeparator(MAINNET_CHAIN_ID);
        bytes32 mainnetHash = _eip712(mainnetDomain, structHash);
        forkHash = src.legacy ? mainnetHash : _eip712(_domainSeparator(block.chainid), structHash);

        info(string.concat("domain hash      ", str(mainnetDomain)));
        info(string.concat("message hash     ", str(structHash)));
        info(string.concat("safeTxHash       ", str(mainnetHash)));
        if (src.legacy) {
            info(string.concat("(EIP-712 domain is { verifyingContract } only: ", src.version, " does not bind signatures to a chain id)"));
        } else {
            info("(EIP-712 domain is { chainId: 1, verifyingContract }; these are the mainnet values)");
            info(string.concat("(on this fork, chain id ", str(block.chainid), ", the same transaction hashes to ", str(forkHash), ")"));
        }
        check(_onchainHash(t) == forkHash, "hash computation matches the Safe's own getTransactionHash()");

        string memory claimed = vm.parseJsonString(vm.readFile(string.concat(runDir, "/tx.json")), ".safeTxHash");
        if (bytes(claimed).length > 0) {
            check(
                vm.parseBytes32(claimed) == mainnetHash,
                "safeTxHash matches the one reported by the Safe Transaction Service",
                string.concat("Safe Transaction Service reports a different safeTxHash: ", claimed)
            );
        }
    }

    // --------------------------------------------------------- token baseline

    /// For --full: note which of the Safe's tokens it can move before the upgrade, so that a
    /// token that is merely paused or blacklisted is not blamed on the upgrade afterwards.
    function _tokenBaseline() internal {
        if (tokens.length == 0) return;
        uint256[] memory status = new uint256[](tokens.length);
        for (uint256 i; i < tokens.length; i++) {
            status[i] = _tryTokenTransfer(tokens[i]);
        }
        string memory k = "baseline";
        vm.serializeAddress(k, "tokens", tokens);
        vm.writeJson(vm.serializeUint(k, "status", status), string.concat(runDir, "/baseline.json"));
    }

    // -------------------------------------------------------------- execution

    function _simulateAndBroadcast(SafeTx memory t, bytes32 txHash, Snapshot memory before) internal returns (bool) {
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
        bool innerOk = _events(logs, before);
        if (!innerOk) {
            fail("the inner call failed. On a pre-1.3.0 Safe this does not revert: on mainnet it would burn the nonce and change nothing else");
            return false;
        }
        pass("execTransaction succeeds with threshold owner approvals");

        section("Code that ran");
        _codeThatRan(accesses, t, before);

        section("Storage written");
        _storageWritten(accesses, txHash, before);

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

    function _events(Vm.Log[] memory logs, Snapshot memory before) internal returns (bool innerOk) {
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
                masterCopy = abi.decode(l.data, (address)) == expSingleton;
            } else if (t0 == EV_CHANGED_FALLBACK_HANDLER) {
                // Indexed from 1.4.1 on; in the data before that.
                address h = l.topics.length > 1 ? address(uint160(uint256(l.topics[1]))) : abi.decode(l.data, (address));
                handler = h == expHandler;
            } else if (t0 != EV_SAFE_MULTISIG_TRANSACTION) {
                warn(string.concat("unexpected event from the Safe, topic0 ", str(t0)));
            }
        }
        innerOk = success && !failure;
        if (innerOk) {
            check(masterCopy, string.concat("emits ChangedMasterCopy(", _name(expSingleton), ")"));
            if (setsHandler && before.fallbackHandler != expHandler) {
                check(handler, string.concat("emits ChangedFallbackHandler(", _name(expHandler), ")"));
            }
        }
    }

    function _codeThatRan(Vm.AccountAccess[] memory acc, SafeTx memory t, Snapshot memory before) internal {
        address[] memory seen = new address[](acc.length);
        address guard = address(uint160(uint256(before.guard)));
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
            bool expected = a.account == address(safe) || a.account == before.singleton || a.account == expSingleton
                || (a.account == t.to && (C.isMultiSendCallOnly(t.to) || C.isMultiSend(t.to) || t.to == tgt.migration));
            if (expected) {
                info(named(a.account));
            } else if (guard != address(0) && a.account == guard) {
                info(string.concat(str(a.account), " (the Safe's transaction guard)"));
            } else {
                fail(string.concat("unexpected contract executed: ", named(a.account)));
                clean = false;
            }
        }
        if (clean) pass("only the Safe, its old and new singletons and the upgrade helper executed; no ETH moved");
    }

    function _storageWritten(Vm.AccountAccess[] memory acc, bytes32 txHash, Snapshot memory before) internal {
        Write[] memory w = _netWrites(acc);
        bool sawSingleton;
        bool sawNonce;
        bool sawHandler;
        bool clean = true;
        bool handlerShouldChange = setsHandler && before.fallbackHandler != expHandler;

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
                if (_asAddr(w[i].prev) != before.singleton || w[i].next != bytes32(uint256(uint160(expSingleton)))) {
                    fail(string.concat("singleton slot does not end as exactly the ", _name(expSingleton)));
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
                if (w[i].next != bytes32(uint256(uint160(expHandler)))) {
                    fail(string.concat("fallback handler does not end as ", named(expHandler)));
                    clean = false;
                }
            } else if (_isApprovalSlot(w[i].slot, txHash) && w[i].next == bytes32(0)) {
                info("approvedHashes[owner][safeTxHash]: 1 -> 0 (simulation artefact: an on-chain approval being consumed)");
            } else {
                fail(string.concat("unexpected storage write: ", _slotName(w[i].slot, before), " ", str(w[i].slot), ": ", change));
                clean = false;
            }
        }
        if (!sawSingleton) fail("singleton slot was not written");
        if (!sawNonce) fail("nonce slot was not written");
        if (handlerShouldChange && !sawHandler) fail("fallback handler slot was not written");
        if (clean && sawSingleton && sawNonce && (sawHandler || !handlerShouldChange)) {
            pass(sawHandler ? "the only lasting changes are singleton, fallback handler and nonce" : "the only lasting changes are singleton and nonce");
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

    function _isApprovalSlot(bytes32 slot, bytes32 txHash) private view returns (bool) {
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
