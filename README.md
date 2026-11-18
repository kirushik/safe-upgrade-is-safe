# safe-dryrun

Rehearse a Safe contract upgrade on a private Anvil fork of mainnet before anyone signs the
real thing. Built for 1.1.1 → 1.5.0; also handles 1.2.0, 1.3.0 and 1.4.1 Safes (L1 and L2
singletons) and the targets 1.3.0, 1.4.1 and 1.5.0.

The real upgrade is proposed and signed in the Safe web UI. This tool takes the transaction the
UI proposed, executes it against a fork, and reports exactly what it does and whether the Safe
still works afterwards.

## Safety model

- Mainnet is only read: state through `ETH_RPC_URL`, queued transactions through the Safe
  Transaction Service. Every write goes to an Anvil process bound to `127.0.0.1`.
- The fork runs with chain id 31337. Pre-1.3.0 Safe signatures are not bound to a chain id, so the
  fork must never be something a wallet or the Safe UI could mistake for mainnet. Do not point
  either at it.
- No keys and no signatures. Owners are impersonated on the fork: all but one call
  `approveHash`, the last one submits `execTransaction`.

## Setup

```sh
direnv allow            # or: nix develop
cp .env.example .env    # set ETH_RPC_URL to a mainnet endpoint you trust
./safe-dryrun doctor    # compare built-in addresses with safe-deployments and mainnet
```

`.envrc` is two lines (`use flake` and `dotenv_if_exists .env`); recreate it if your global
gitignore keeps it out of the repository.

## Use

```sh
# Before proposing anything: rehearse the batch the Safe UI is expected to build
./safe-dryrun 0xYourSafe --reference

# After proposing in the Safe UI: rehearse the transaction that is actually queued
./safe-dryrun 0xYourSafe
./safe-dryrun 0xYourSafe --tx-hash 0x…      # if several are queued at the same nonce
./safe-dryrun 0xYourSafe --tx-file tx.json  # or from a file

# Upgrade to something other than Safe 1.5.0 (L1)
./safe-dryrun 0xYourSafe --target 1.4.1
./safe-dryrun 0xYourSafe --l2              # expect the SafeL2 singleton of the target

# Run the extended test suite on the upgraded Safe
./safe-dryrun 0xYourSafe --full
./safe-dryrun 0xYourSafe --full --token 0xSomeErc20

# Leave the fork up afterwards to poke at it with cast
./safe-dryrun 0xYourSafe --keep
```

The Safe's current version is detected from its singleton. The expected upgrade transaction
depends on it, mirroring what the Safe UI builds:

- 1.1.1 and 1.2.0: a MultiSendCallOnly batch of `changeMasterCopy(target singleton)` and
  `setFallbackHandler(target handler)`.
- 1.3.0 and 1.4.1: a delegatecall to the target version's `SafeMigration` contract, using
  `migrateWithFallbackHandler()` when the Safe has the stock handler for its version and
  `migrateSingleton()` (handler kept) otherwise. There is no `SafeMigration` for 1.3.0, so
  1.3.0 is only a target for older Safes.

Exit status is 0 for pass (possibly with warnings), 1 if any check failed, 2 for usage or
environment errors. Each run leaves its report, snapshots and logs in `runs/<safe>-<time>/`.

Before signing on a hardware wallet, compare the domain hash, message hash and safeTxHash
printed under "What signers will see" with what the device shows. For 1.3.0+ Safes the hash
depends on the chain id; the report prints the mainnet values, not the fork's.

## What is checked

Before:
the Safe is on a known canonical singleton older than the target, behind a standard proxy; its
signing domain is the one expected for its version; guard and module-guard slots hold nothing
that would wake up; fallback handler, modules and contract owners are classified.

The transaction:
it is exactly the upgrade described above for this Safe and target; no value, no refund; the
safeTxHash agrees with the Safe's own `getTransactionHash` and with the Transaction Service.

Execution:
which contracts ran code, whether ETH moved, and every storage slot written. Anything beyond
singleton, fallback handler and nonce fails the run.

After (read back from the fork):
singleton, `VERSION()`, handler and nonce are as expected; owners, threshold, modules, balance,
guards and proxy code are unchanged; whether queued transactions survive the upgrade (they do
from 1.3.0 on, they do not from older versions, whose signing domain changes).

Smoke tests on the upgraded Safe (simulated on top of the fork, not written to it):
receive and send ETH, add and remove an owner, ECDSA signature, module enable and execute,
MultiSendCallOnly batch, revert-on-inner-failure; with the stock handler also EIP-1271,
`getModules` and token callbacks; from pre-1.3.0 also rejection of old-domain approvals.

With `--full`, additionally:

- every owner in turn can take part in a transaction; fewer approvals than the threshold are
  rejected; a non-owner's approval does not count; a signed transaction cannot be replayed
- `eth_sign` and contract-owner (EIP-1271) signatures
- threshold change, owner swap, transaction guard install and removal, gas refund
- the Safe can move the ETH and ERC-20 tokens it actually holds. Tokens come from the Safe
  Transaction Service's trusted list plus any `--token`; about 1% of each balance is moved
  and rolled back. A token that could not be moved before the upgrade either is reported as
  a warning, not blamed on the upgrade.

## Limits

- Mainnet only. 1.0.0 Safes are not supported. 1.2.0 is supported on paper but was never run
  against a real Safe (none turned up); 1.1.1, 1.3.0 and 1.4.1 were.
- For a Safe on an L2 singleton the default expectation is the L1 singleton of the target, which
  is what the Safe UI source does on mainnet; use `--l2` if your transaction says otherwise.
- Existing modules, guards, nested Safes and dapp integrations are flagged, not exercised.
- The pre-1.3.0 reference batch uses MultiSendCallOnly 1.3.0 as a stand-in; the UI may pick
  another official MultiSend deployment, which the checks accept.
- A transaction can only be rehearsed when its nonce is the Safe's current nonce.
- A fork of the latest block on a non-archive RPC goes stale after a while; restart rather
  than keeping one fork up for hours.

## Layout

- `safe-dryrun` — the CLI: picks the transaction, starts Anvil, runs the two phases, prints the verdict.
- `script/Execute.s.sol` — inspects the Safe, dissects the transaction, records the state diff, replays it on the fork.
- `script/Verify.s.sol` — post-upgrade comparison and smoke tests.
- `src/SafeConstants.sol` — canonical addresses, storage slots, EIP-712 type hashes.
- `src/SafeVersions.sol` — what identifies each version and what an upgrade to it leaves behind.
