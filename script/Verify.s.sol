// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DryRunBase} from "./DryRunBase.sol";
import {ISafe, IMultiSend} from "../src/ISafe.sol";
import {SafeConstants as C} from "../src/SafeConstants.sol";

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

/// Phase 2: read the upgraded Safe back from the Anvil fork, compare it with the pre-upgrade
/// snapshot, then exercise it. The exercises run inside this script's private simulation and are
/// never broadcast, so the fork is left exactly as the upgrade transaction left it.
///
/// Env: SAFE, RUN_DIR.
contract Verify is DryRunBase {
    address[] private signers;
    uint256 private constant TEST_KEY = uint256(keccak256("safe-dryrun throwaway owner"));
    address private constant RECIPIENT = address(uint160(uint256(keccak256("safe-dryrun recipient"))));
    address private constant STRANGER = address(uint160(uint256(keccak256("safe-dryrun stranger"))));

    function run() external {
        _init("verify");
        Snapshot memory before = _readSnapshot("before");
        Snapshot memory afterward = _snapshot();
        _writeSnapshot(afterward, "after");
        signers = _pickSigners(afterward.owners, afterward.threshold);

        section("Safe after the upgrade");
        _printSnapshot(afterward);

        section("Upgrade result");
        check(afterward.singleton == C.SAFE_150, "storage slot 0 is exactly the Safe 1.5.0 singleton");
        check(safe.masterCopy() == C.SAFE_150, "proxy's masterCopy() returns the Safe 1.5.0 singleton");
        check(keccak256(bytes(afterward.version)) == keccak256("1.5.0"), "VERSION() is 1.5.0");
        check(afterward.fallbackHandler == C.COMPAT_FALLBACK_HANDLER_150, "fallback handler is CompatibilityFallbackHandler 1.5.0");
        check(afterward.nonce == before.nonce + 1, "nonce advanced by exactly one");

        section("Nothing else moved");
        check(_sameAddresses(before.owners, afterward.owners) && afterward.ownerCount == before.ownerCount, "owners unchanged (same set, same order)");
        check(afterward.threshold == before.threshold, "threshold unchanged");
        check(_sameAddresses(before.modules, afterward.modules), "modules unchanged");
        check(afterward.balance == before.balance, "ETH balance unchanged");
        check(afterward.guard == bytes32(0) && afterward.moduleGuard == bytes32(0), "no transaction guard or module guard is set");
        check(afterward.proxyCodehash == before.proxyCodehash, "proxy bytecode unchanged");
        check(afterward.legacyDomainSeparator == before.legacyDomainSeparator, "legacy domain separator slot untouched (now dead storage)");
        _forkMatchesRehearsal();
        _noApprovalResidue(before);

        section("Signing domain from now on");
        check(safe.domainSeparator() == _domainSeparator(block.chainid), "domainSeparator() is now derived from the chain id");
        info(string.concat("on this fork (chain ", str(block.chainid), "): ", str(_domainSeparator(block.chainid))));
        info(string.concat("on mainnet (chain 1):       ", str(_domainSeparator(MAINNET_CHAIN_ID))));
        info("Anything signed or approved for this Safe before the upgrade (queued transactions,");
        info("approveHash entries, signed messages) used the old domain and is void afterwards.");

        section("Smoke tests on the upgraded Safe (simulated, not written to the fork)");
        _smoke("receives plain ETH", this.smokeReceive.selector);
        _smoke("sends ETH with owner approvals", this.smokeSendEth.selector);
        _smoke("adds and removes an owner", this.smokeOwnerRoundTrip.selector);
        _smoke("accepts an ECDSA signature over the chain-id domain", this.smokeEcdsa.selector);
        _smoke("validates EIP-1271 signatures through the new fallback handler", this.smokeEip1271.selector);
        _smoke("enables a module and lets it execute", this.smokeModule.selector);
        _smoke("runs a MultiSendCallOnly 1.5.0 batch", this.smokeMultiSend.selector);
        _smoke("answers token callbacks and ERC-165", this.smokeTokenCallbacks.selector);
        _smoke("rejects approvals made under the old chain-id-less domain", this.smokeLegacyHashRejected.selector);
        _smoke("reverts (instead of burning the nonce) when the inner call fails", this.smokeInnerFailureReverts.selector);

        _finish("verify", true);
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

    function _noApprovalResidue(Snapshot memory before) internal {
        bytes32 txHash = vm.parseJsonBytes32(vm.readFile(string.concat(runDir, "/statediff.json")), ".safeTxHash");
        bool clean = true;
        for (uint256 i; i < before.owners.length; i++) {
            if (safe.approvedHashes(before.owners[i], txHash) != 0) clean = false;
        }
        check(clean, "no leftover approveHash entries from the simulation");
    }

    // ------------------------------------------------------------ smoke tests

    function _smoke(string memory name, bytes4 selector) internal {
        uint256 snap = vm.snapshotState();
        (bool ok, bytes memory ret) = address(this).call(abi.encodeWithSelector(selector));
        vm.revertToState(snap);
        if (ok) pass(name);
        else fail(string.concat(name, ": ", _revertReason(ret)));
    }

    /// Executes a Safe transaction the same way the upgrade itself was executed: impersonated
    /// owners approve the hash on-chain, the lowest-addressed one submits.
    function _exec(address to, uint256 value, bytes memory data, uint8 operation) internal returns (bool) {
        SafeTx memory t = SafeTx(to, value, data, operation, 0, 0, 0, address(0), address(0), safe.nonce());
        bytes32 h = _onchainHash(t);
        require(h == _eip712(_domainSeparator(block.chainid), _structHash(t)), "getTransactionHash disagrees with the EIP-712 chain-id domain");
        return _execApproved(t, h);
    }

    function _execApproved(SafeTx memory t, bytes32 hashToApprove) internal returns (bool ok) {
        for (uint256 i = 1; i < signers.length; i++) {
            vm.prank(signers[i]);
            safe.approveHash(hashToApprove);
        }
        vm.prank(signers[0]);
        bytes memory ret;
        (ok, ret) = address(safe).call(_execCalldata(t, _approvedSignatures(signers)));
        if (ok) ok = abi.decode(ret, (bool));
    }

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
        require(_exec(RECIPIENT, 1 ether, "", 0), "execTransaction failed");
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

    function _addTestOwnerWithThresholdOne() internal returns (address extra) {
        extra = vm.addr(TEST_KEY);
        require(_exec(address(safe), 0, abi.encodeCall(ISafe.addOwnerWithThreshold, (extra, 1)), 0), "could not add test owner");
    }

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TEST_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function smokeEcdsa() external {
        _addTestOwnerWithThresholdOne();
        vm.deal(address(safe), address(safe).balance + 1 ether);
        SafeTx memory t = SafeTx(RECIPIENT, 1 ether, "", 0, 0, 0, 0, address(0), address(0), safe.nonce());
        bytes32 digest = _eip712(_domainSeparator(block.chainid), _structHash(t));
        vm.prank(STRANGER);
        (bool ok,) = address(safe).call(_execCalldata(t, _sign(digest)));
        require(ok && RECIPIENT.balance == 1 ether, "ECDSA-signed transaction was not executed");
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
        address[] memory listed = safe.getModules();
        require(listed.length > 0 && listed[0] == address(module), "getModules() via fallback handler does not list the module");
        vm.deal(address(safe), address(safe).balance + 1 ether);
        require(module.exec(safe, RECIPIENT, 1 ether) && RECIPIENT.balance == 1 ether, "module execution failed");
    }

    function smokeMultiSend() external {
        vm.deal(address(safe), address(safe).balance + 3 wei);
        bytes memory batch = abi.encodePacked(
            uint8(0), RECIPIENT, uint256(1), uint256(0), uint8(0), STRANGER, uint256(2), uint256(0)
        );
        uint256 strangerBefore = STRANGER.balance;
        require(_exec(C.MULTISEND_CALL_ONLY_150, 0, abi.encodeCall(IMultiSend.multiSend, (batch)), 1), "batch failed");
        require(RECIPIENT.balance == 1 && STRANGER.balance == strangerBefore + 2, "batch transfers did not arrive");
    }

    function smokeTokenCallbacks() external {
        require(safe.onERC721Received(address(0), address(0), 0, "") == bytes4(0x150b7a02), "ERC-721 callback");
        require(safe.onERC1155Received(address(0), address(0), 0, 0, "") == bytes4(0xf23a6e61), "ERC-1155 callback");
        require(safe.supportsInterface(0x01ffc9a7), "ERC-165");
    }

    function smokeLegacyHashRejected() external {
        SafeTx memory t = SafeTx(RECIPIENT, 0, "", 0, 0, 0, 0, address(0), address(0), safe.nonce());
        bytes32 legacy = _eip712(_legacyDomainSeparator(), _structHash(t));
        require(legacy != _onchainHash(t), "hash did not change with the upgrade");
        uint256 n = safe.nonce();
        require(!_execApproved(t, legacy), "a transaction approved under the old domain was executed");
        require(safe.nonce() == n, "nonce moved");
    }

    function smokeInnerFailureReverts() external {
        Reverter target = new Reverter();
        uint256 n = safe.nonce();
        SafeTx memory t = SafeTx(address(target), 0, "", 0, 0, 0, 0, address(0), address(0), n);
        require(!_execApproved(t, _onchainHash(t)), "transaction with a failing inner call did not revert");
        require(safe.nonce() == n, "nonce was consumed");
    }
}
