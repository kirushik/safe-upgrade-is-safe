// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DryRunBase} from "./DryRunBase.sol";
import {ISafe, IMultiSend} from "../src/ISafe.sol";
import {SafeConstants as C} from "../src/SafeConstants.sol";
import {SafeVersions as V} from "../src/SafeVersions.sol";

contract MockModule {
    function exec(ISafe safe, address to, uint256 value) external returns (bool) {
        return safe.execTransactionFromModule(to, value, "", 0);
    }
}

contract Reverter {
    fallback() external payable {
        revert("nope");
    }
}

/// A contract owner that approves everything, in both EIP-1271 dialects Safes have spoken.
contract MockContractOwner {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }

    function isValidSignature(bytes calldata, bytes calldata) external pure returns (bytes4) {
        return 0x20c13b0b;
    }
}

/// A transaction guard that allows everything and counts how often it is consulted.
contract MockGuard {
    uint256 public calls;

    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }

    fallback() external {
        calls++;
    }
}

/// Phase 2: read the upgraded Safe back from the Anvil fork, compare it with the pre-upgrade
/// snapshot, then exercise it. The exercises run inside this script's private simulation and are
/// never broadcast, so the fork is left exactly as the upgrade transaction left it.
///
/// Env: SAFE, RUN_DIR, TARGET, TARGET_L2, FULL, TOKENS.
contract Verify is DryRunBase {
    uint256 private constant TEST_KEY = uint256(keccak256("safe-dryrun throwaway owner"));
    address private constant STRANGER = address(uint160(uint256(keccak256("safe-dryrun stranger"))));

    address private expSingleton;
    address private expHandler;
    bool private legacySource;
    /// Handler-dependent checks only make sense when the target's stock handler is installed.
    bool private stockHandler;

    function run() external {
        _init("verify");
        string memory e = vm.readFile(string.concat(runDir, "/expected.json"));
        expSingleton = vm.parseJsonAddress(e, ".singleton");
        expHandler = vm.parseJsonAddress(e, ".handler");
        legacySource = vm.parseJsonBool(e, ".legacySource");
        string memory sourceVersion = vm.parseJsonString(e, ".sourceVersion");

        Snapshot memory before = _readSnapshot("before");
        Snapshot memory afterward = _snapshot();
        _writeSnapshot(afterward, "after");
        signers = _pickSigners(afterward.owners, afterward.threshold);
        stockHandler = afterward.fallbackHandler == tgt.handler;

        section("Safe after the upgrade");
        _printSnapshot(afterward);

        section("Upgrade result");
        if (afterward.singleton == before.singleton && afterward.nonce == before.nonce + 1) {
            fail("the transaction was mined on the fork but its inner call failed: the nonce is used up and nothing was upgraded. On a pre-1.3.0 Safe this is what too small a safeTxGas does, and it would happen on mainnet too");
        }
        check(afterward.singleton == expSingleton, string.concat("storage slot 0 is exactly the ", _name(expSingleton)));
        check(safe.masterCopy() == expSingleton, "proxy's masterCopy() returns the new singleton");
        check(keccak256(bytes(afterward.version)) == keccak256(bytes(tgt.version)), string.concat("VERSION() is ", tgt.version));
        if (afterward.fallbackHandler == expHandler && stockHandler) {
            pass(string.concat("fallback handler is ", _name(expHandler)));
        } else if (afterward.fallbackHandler == expHandler) {
            warn(string.concat("fallback handler was kept as ", named(expHandler), ", not the stock ", tgt.version, " handler: handler-dependent tests are skipped"));
        } else {
            fail(string.concat("fallback handler is ", named(afterward.fallbackHandler), ", expected ", named(expHandler)));
        }
        check(afterward.nonce == before.nonce + 1, "nonce advanced by exactly one");

        section("Nothing else moved");
        check(_sameAddresses(before.owners, afterward.owners) && afterward.ownerCount == before.ownerCount, "owners unchanged (same set, same order)");
        check(afterward.threshold == before.threshold && safe.getThreshold() == before.threshold, string.concat("threshold unchanged (", str(before.threshold), " of ", str(before.owners.length), ")"));
        check(_sameAddresses(before.modules, afterward.modules), "modules unchanged");
        check(afterward.balance == before.balance, "ETH balance unchanged");
        check(afterward.guard == before.guard && afterward.moduleGuard == before.moduleGuard, "transaction guard and module guard slots unchanged");
        check(afterward.proxyCodehash == before.proxyCodehash, "proxy bytecode unchanged");
        check(afterward.legacyDomainSeparator == before.legacyDomainSeparator, "storage slot 6 (old domain separator) untouched");
        _forkMatchesRehearsal();
        _approvalResidue(before);

        section("Signing domain from now on");
        check(safe.domainSeparator() == _domainSeparator(block.chainid), "domainSeparator() is derived from the chain id");
        info(string.concat("on this fork (chain ", str(block.chainid), "): ", str(_domainSeparator(block.chainid))));
        info(string.concat("on mainnet (chain 1):       ", str(_domainSeparator(MAINNET_CHAIN_ID))));
        if (legacySource) {
            info("Anything signed or approved for this Safe before the upgrade (queued transactions,");
            info("approveHash entries, signed messages) used the old domain and is void afterwards.");
        } else {
            info(string.concat("Unchanged from ", sourceVersion, ": transactions already queued at later nonces keep their hashes and signatures."));
        }

        section("Smoke tests on the upgraded Safe (simulated, not written to the fork)");
        _smoke("receives plain ETH", this.smokeReceive.selector);
        _smoke("sends ETH with owner approvals", this.smokeSendEth.selector);
        _smoke("adds and removes an owner", this.smokeOwnerRoundTrip.selector);
        _smoke("accepts an ECDSA signature over the chain-id domain", this.smokeEcdsa.selector);
        _smoke("enables a module and lets it execute", this.smokeModule.selector);
        _smoke(string.concat("runs a MultiSendCallOnly ", tgt.version, " batch"), this.smokeMultiSend.selector);
        _smoke("reverts (instead of burning the nonce) when the inner call fails", this.smokeInnerFailureReverts.selector);
        if (stockHandler) {
            _smoke("validates EIP-1271 signatures through the fallback handler", this.smokeEip1271.selector);
            _smoke("lists modules through the fallback handler", this.smokeGetModules.selector);
            _smoke("answers token callbacks and ERC-165", this.smokeTokenCallbacks.selector);
        }
        if (legacySource) {
            _smoke("rejects approvals made under the old chain-id-less domain", this.smokeLegacyHashRejected.selector);
        }

        if (full) _fullSuite(afterward);

        _finish("verify", true);
    }

    function _fullSuite(Snapshot memory s) internal {
        section("Full suite: who can authorise transactions");
        _smoke(string.concat("every one of the ", str(s.owners.length), " owners can take part in a transaction"), this.fullEveryOwnerCanSign.selector);
        _smoke(string.concat("fewer than ", str(s.threshold), " approval(s) are rejected"), this.fullThresholdEnforced.selector);
        _smoke("an approval from a non-owner does not count", this.fullNonOwnerRejected.selector);
        _smoke("a signed transaction cannot be replayed", this.fullReplayRejected.selector);

        section("Full suite: signature types");
        _smoke("eth_sign (personal-message) signatures", this.fullEthSign.selector);
        _smoke("contract-owner signatures (EIP-1271)", this.fullContractSignature.selector);

        section("Full suite: owner and policy management");
        _smoke("changes the threshold and honours the new value", this.fullChangeThreshold.selector);
        _smoke("swaps an owner", this.fullSwapOwner.selector);
        if (s.guard == bytes32(0)) {
            _smoke("installs, consults and removes a transaction guard", this.fullGuard.selector);
        } else {
            info("guard test skipped: this Safe already has a transaction guard");
        }
        _smoke("pays a gas refund when one is requested", this.fullGasRefund.selector);

        section("Full suite: moving the Safe's real assets");
        if (s.balance > 0) {
            _smoke("sends 1 wei of its own ETH balance", this.fullSendOwnEth.selector);
        } else {
            info("the Safe holds no ETH");
        }
        _tokens();
    }

    // ------------------------------------------------------------ comparisons

    function _forkMatchesRehearsal() internal {
        string memory j = vm.readFile(string.concat(runDir, "/statediff.json"));
        address[] memory accounts = vm.parseJsonAddressArray(j, ".accounts");
        bytes32[] memory slots = vm.parseJsonBytes32Array(j, ".slots");
        bytes32[] memory values = vm.parseJsonBytes32Array(j, ".values");
        bool same = true;
        for (uint256 i; i < slots.length; i++) {
            if (vm.load(accounts[i], slots[i]) != values[i]) same = false;
        }
        check(same, "fork storage matches the rehearsed state diff slot for slot");
    }

    function _approvalResidue(Snapshot memory before) internal {
        bytes32 txHash = vm.parseJsonBytes32(vm.readFile(string.concat(runDir, "/statediff.json")), ".safeTxHash");
        uint256 left;
        for (uint256 i; i < before.owners.length; i++) {
            if (safe.approvedHashes(before.owners[i], txHash) != 0) left++;
        }
        if (left == 0) {
            pass("no leftover approveHash entries from the simulation");
        } else if (legacySource) {
            fail("approveHash entries from the simulation were not consumed");
        } else {
            info(string.concat(str(left), " approveHash entr", left == 1 ? "y" : "ies", " from the simulation remain on the fork (1.3.0+ never clears them; real signatures leave none)"));
        }
    }

    function _tokens() internal {
        if (tokens.length == 0) {
            info("no tokens to test (none found for this Safe, and none given with --token)");
            return;
        }
        string memory j = vm.readFile(string.concat(runDir, "/baseline.json"));
        uint256[] memory was = vm.parseJsonUintArray(j, ".status");
        for (uint256 i; i < tokens.length; i++) {
            string memory label = string.concat("token ", _symbol(tokens[i]), " ", str(tokens[i]));
            uint256 now_ = _tryTokenTransfer(tokens[i]);
            if (now_ == 0) info(string.concat(label, ": the Safe holds none"));
            else if (now_ == 1) pass(string.concat(label, ": transfer arrives"));
            else if (was[i] == 1) fail(string.concat(label, ": transfer worked before the upgrade and fails after it"));
            else warn(string.concat(label, ": transfer fails, and already failed before the upgrade (paused, blacklisted or non-standard token?)"));
        }
    }

    function _symbol(address token) internal view returns (string memory) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSignature("symbol()"));
        if (!ok || ret.length < 96) return "?";
        // Fetched from the chain, so keep it short and printable before it goes into a report.
        bytes memory raw = bytes(abi.decode(ret, (string)));
        uint256 n = raw.length > 12 ? 12 : raw.length;
        bytes memory out = new bytes(n);
        for (uint256 i; i < n; i++) {
            out[i] = raw[i] >= 0x21 && raw[i] <= 0x7e ? raw[i] : bytes1("?");
        }
        return string(out);
    }

    // ---------------------------------------------------------------- harness

    function _smoke(string memory name, bytes4 selector) internal {
        uint256 snap = vm.snapshotState();
        (bool ok, bytes memory ret) = address(this).call(abi.encodeWithSelector(selector));
        vm.revertToState(snap);
        if (ok) pass(name);
        else fail(string.concat(name, ": ", _revertReason(ret)));
    }

    function _noop() internal view returns (SafeTx memory) {
        return _plainTx(RECIPIENT, 0, "", 0);
    }

    function _addTestOwnerWithThresholdOne() internal returns (address extra) {
        extra = vm.addr(TEST_KEY);
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.addOwnerWithThreshold, (extra, 1)), 0), "could not add test owner");
    }

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TEST_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _submit(SafeTx memory t, bytes memory sigs) internal returns (bool ok) {
        vm.prank(STRANGER);
        bytes memory ret;
        (ok, ret) = address(safe).call(_execCalldata(t, sigs));
        if (ok) ok = abi.decode(ret, (bool));
    }

    // ------------------------------------------------------------ smoke tests

    function smokeReceive() external {
        vm.deal(STRANGER, 1 ether);
        uint256 b = address(safe).balance;
        vm.prank(STRANGER);
        (bool ok,) = address(safe).call{value: 1 wei}("");
        require(ok && address(safe).balance == b + 1, "plain ETH transfer was not accepted");
    }

    function smokeSendEth() external {
        vm.deal(address(safe), address(safe).balance + 1 ether);
        uint256 n = safe.nonce();
        SafeTx memory t = _plainTx(RECIPIENT, 1 ether, "", 0);
        require(_onchainHash(t) == _eip712(_domainSeparator(block.chainid), _structHash(t)), "getTransactionHash disagrees with the EIP-712 chain-id domain");
        require(_execWith(signers, t, _onchainHash(t)), "execTransaction failed");
        require(RECIPIENT.balance == 1 ether, "recipient did not receive the ETH");
        require(safe.nonce() == n + 1, "nonce did not advance");
    }

    function smokeOwnerRoundTrip() external {
        address extra = vm.addr(TEST_KEY);
        address[] memory original = safe.getOwners();
        uint256 threshold = safe.getThreshold();
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.addOwnerWithThreshold, (extra, threshold)), 0), "addOwner failed");
        require(safe.isOwner(extra) && safe.getOwners().length == original.length + 1, "owner was not added");
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.removeOwner, (C.SENTINEL, extra, threshold)), 0), "removeOwner failed");
        require(_sameAddresses(original, safe.getOwners()) && safe.getThreshold() == threshold, "owner set did not return to the original");
    }

    function smokeEcdsa() external {
        _addTestOwnerWithThresholdOne();
        vm.deal(address(safe), address(safe).balance + 1 ether);
        SafeTx memory t = _plainTx(RECIPIENT, 1 ether, "", 0);
        bytes32 digest = _eip712(_domainSeparator(block.chainid), _structHash(t));
        require(_submit(t, _sign(digest)) && RECIPIENT.balance == 1 ether, "ECDSA-signed transaction was not executed");
    }

    function smokeEip1271() external {
        _addTestOwnerWithThresholdOne();
        bytes32 dataHash = keccak256("safe-dryrun message");
        bytes32 messageHash = safe.getMessageHash(abi.encode(dataHash));
        require(safe.isValidSignature(dataHash, _sign(messageHash)) == bytes4(0x1626ba7e), "valid signature was not accepted");
        try safe.isValidSignature(keccak256("something else"), _sign(messageHash)) returns (bytes4 magic) {
            require(magic != bytes4(0x1626ba7e), "signature over a different message was accepted");
        } catch {}
    }

    function smokeModule() external {
        MockModule module = new MockModule();
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.enableModule, (address(module))), 0), "enableModule failed");
        require(safe.isModuleEnabled(address(module)), "module not enabled");
        vm.deal(address(safe), address(safe).balance + 1 ether);
        require(module.exec(safe, RECIPIENT, 1 ether) && RECIPIENT.balance == 1 ether, "module execution failed");
    }

    function smokeGetModules() external {
        MockModule module = new MockModule();
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.enableModule, (address(module))), 0), "enableModule failed");
        address[] memory listed = safe.getModules();
        require(listed.length > 0 && listed[0] == address(module), "getModules() does not list a freshly enabled module");
    }

    function smokeMultiSend() external {
        vm.deal(address(safe), address(safe).balance + 3 wei);
        bytes memory batch = abi.encodePacked(
            uint8(0), RECIPIENT, uint256(1), uint256(0), uint8(0), STRANGER, uint256(2), uint256(0)
        );
        uint256 strangerBefore = STRANGER.balance;
        require(_exec(tgt.multiSendCallOnly, 0, abi.encodeCall(IMultiSend.multiSend, (batch)), 1), "batch failed");
        require(RECIPIENT.balance == 1 && STRANGER.balance == strangerBefore + 2, "batch transfers did not arrive");
    }

    function smokeTokenCallbacks() external {
        require(safe.onERC721Received(address(0), address(0), 0, "") == bytes4(0x150b7a02), "ERC-721 callback");
        require(safe.onERC1155Received(address(0), address(0), 0, 0, "") == bytes4(0xf23a6e61), "ERC-1155 callback");
        require(safe.supportsInterface(0x01ffc9a7), "ERC-165");
    }

    function smokeLegacyHashRejected() external {
        SafeTx memory t = _noop();
        bytes32 legacy = _eip712(_legacyDomainSeparator(), _structHash(t));
        require(legacy != _onchainHash(t), "hash did not change with the upgrade");
        uint256 n = safe.nonce();
        require(!_execWith(signers, t, legacy), "a transaction approved under the old domain was executed");
        require(safe.nonce() == n, "nonce moved");
    }

    function smokeInnerFailureReverts() external {
        Reverter target = new Reverter();
        uint256 n = safe.nonce();
        SafeTx memory t = _plainTx(address(target), 0, "", 0);
        require(!_execWith(signers, t, _onchainHash(t)), "transaction with a failing inner call did not revert");
        require(safe.nonce() == n, "nonce was consumed");
    }

    // ------------------------------------------------------------- full suite

    /// Each owner in turn, joined by as many of the lowest-addressed other owners as the
    /// threshold needs.
    function fullEveryOwnerCanSign() external {
        address[] memory owners = safe.getOwners();
        uint256 threshold = safe.getThreshold();
        address[] memory sorted = _pickSigners(owners, owners.length);
        for (uint256 i; i < owners.length; i++) {
            address[] memory set = new address[](threshold);
            uint256 n;
            for (uint256 j; j < sorted.length && n < threshold - 1; j++) {
                if (sorted[j] != owners[i]) set[n++] = sorted[j];
            }
            set[n] = owners[i];
            set = _pickSigners(set, threshold);
            SafeTx memory t = _noop();
            require(_execWith(set, t, _onchainHash(t)), string.concat("a transaction co-signed by owner ", str(owners[i]), " failed"));
        }
    }

    function fullThresholdEnforced() external {
        uint256 threshold = safe.getThreshold();
        address[] memory tooFew = new address[](threshold - 1);
        for (uint256 i; i < tooFew.length; i++) {
            tooFew[i] = signers[i];
        }
        SafeTx memory t = _noop();
        uint256 n = safe.nonce();
        require(!_execWith(tooFew, t, _onchainHash(t)), "a transaction with too few approvals was executed");
        require(safe.nonce() == n, "nonce moved");
        require(_execWith(signers, t, _onchainHash(t)), "a transaction with exactly the threshold was refused");
    }

    function fullNonOwnerRejected() external {
        uint256 threshold = safe.getThreshold();
        address[] memory set = new address[](threshold);
        for (uint256 i; i + 1 < threshold; i++) {
            set[i] = signers[i];
        }
        set[threshold - 1] = STRANGER;
        set = _pickSigners(set, threshold);
        SafeTx memory t = _noop();
        require(!_execWith(set, t, _onchainHash(t)), "a non-owner's approval was counted towards the threshold");
    }

    function fullReplayRejected() external {
        _addTestOwnerWithThresholdOne();
        SafeTx memory t = _noop();
        bytes memory sig = _sign(_onchainHash(t));
        require(_submit(t, sig), "signed transaction was not executed");
        require(!_submit(t, sig), "the same signed transaction executed twice");
    }

    function fullEthSign() external {
        _addTestOwnerWithThresholdOne();
        SafeTx memory t = _noop();
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _onchainHash(t)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TEST_KEY, digest);
        require(_submit(t, abi.encodePacked(r, s, v + 4)), "eth_sign signature was not accepted");
    }

    function fullContractSignature() external {
        MockContractOwner owner = new MockContractOwner();
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.addOwnerWithThreshold, (address(owner), 1)), 0), "could not add contract owner");
        SafeTx memory t = _noop();
        // r = signer, s = offset of the dynamic part, v = 0, then length-prefixed signature bytes.
        bytes memory sig = abi.encodePacked(bytes32(uint256(uint160(address(owner)))), uint256(65), uint8(0), uint256(1), bytes1(0x01));
        require(_submit(t, sig), "contract-owner signature was not accepted");
    }

    function fullChangeThreshold() external {
        address[] memory owners = safe.getOwners();
        uint256 original = safe.getThreshold();
        uint256 other = original == 1 ? (owners.length > 1 ? 2 : 1) : 1;
        if (other == original) return; // single-owner Safe: nothing to vary
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.changeThreshold, (other)), 0), "changeThreshold failed");
        require(safe.getThreshold() == other, "threshold did not change");
        address[] memory set = _pickSigners(owners, other);
        SafeTx memory t = _plainTx(address(safe), 0, abi.encodeCall(ISafe.changeThreshold, (original)), 0);
        require(_execWith(set, t, _onchainHash(t)), "transaction under the new threshold failed");
        require(safe.getThreshold() == original, "threshold did not change back");
    }

    function fullSwapOwner() external {
        address[] memory owners = safe.getOwners();
        address extra = vm.addr(TEST_KEY);
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.swapOwner, (C.SENTINEL, owners[0], extra)), 0), "swapOwner failed");
        require(safe.isOwner(extra) && !safe.isOwner(owners[0]) && safe.getOwners().length == owners.length, "owner was not swapped");
        address[] memory set = _pickSigners(safe.getOwners(), safe.getThreshold());
        SafeTx memory t = _plainTx(address(safe), 0, abi.encodeCall(ISafe.swapOwner, (C.SENTINEL, extra, owners[0])), 0);
        require(_execWith(set, t, _onchainHash(t)), "swapping back failed");
        require(_sameAddresses(owners, safe.getOwners()), "owner list did not return to the original");
    }

    function fullGuard() external {
        MockGuard guard = new MockGuard();
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(guard))), 0), "setGuard failed");
        uint256 before = guard.calls();
        SafeTx memory t = _noop();
        require(_execWith(signers, t, _onchainHash(t)), "transaction under the guard failed");
        require(guard.calls() == before + 2, "guard was not consulted before and after the transaction");
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), 0), "removing the guard failed");
        require(vm.load(address(safe), C.SLOT_GUARD) == bytes32(0), "guard slot not cleared");
    }

    function fullGasRefund() external {
        vm.deal(address(safe), address(safe).balance + 1 ether);
        vm.txGasPrice(2 gwei);
        SafeTx memory t = SafeTx(STRANGER, 0, "", 0, 50_000, 30_000, 1 gwei, address(0), RECIPIENT, safe.nonce());
        require(_execWith(signers, t, _onchainHash(t)), "transaction with a refund failed");
        require(RECIPIENT.balance > 0, "refund receiver was not paid");
    }

    function fullSendOwnEth() external {
        uint256 b = address(safe).balance;
        require(_exec(RECIPIENT, 1 wei, "", 0), "execTransaction failed");
        require(RECIPIENT.balance == 1 && address(safe).balance == b - 1, "ETH did not move");
    }
}
