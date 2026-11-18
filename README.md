# safe-dryrun

Rehearse a Safe 1.1.1 → 1.5.0 upgrade on a private Anvil fork of mainnet before anyone signs
the real thing.

The real upgrade is proposed and signed in the Safe web UI. This tool takes the transaction the
UI proposed, executes it against a fork, and reports exactly what it does and whether the Safe
still works afterwards.

## Safety model

- Mainnet is only read: state through `ETH_RPC_URL`, queued transactions through the Safe
  Transaction Service. Every write goes to an Anvil process bound to `127.0.0.1`.
- The fork runs with chain id 31337. Safe 1.1.1 signatures are not bound to a chain id, so the
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

# Leave the fork up afterwards to poke at it with cast
./safe-dryrun 0xYourSafe --keep
```

Exit status is 0 for pass (possibly with warnings), 1 if any check failed, 2 for usage or
environment errors. Each run leaves its report, snapshots and logs in `runs/<safe>-<time>/`.

Before signing on a hardware wallet, compare the domain hash, message hash and safeTxHash
printed under "What signers will see" with what the device shows.

## What is checked

Before:
the Safe is on the canonical 1.1.1 singleton behind the standard proxy; the stored domain
separator is the expected legacy one; guard and module-guard slots are empty; fallback handler,
modules and contract owners are classified.

The transaction:
it is a delegatecall to an official MultiSendCallOnly containing exactly
`changeMasterCopy(Safe 1.5.0)` and `setFallbackHandler(CompatibilityFallbackHandler 1.5.0)` on
the Safe itself; no value, no refund; the safeTxHash agrees with the Safe's own
`getTransactionHash` and with the Transaction Service.

Execution:
which contracts ran code, whether ETH moved, and every storage slot written. Anything beyond
singleton, fallback handler and nonce fails the run.

After (read back from the fork):
singleton, `VERSION()`, handler and nonce are as expected; owners, threshold, modules, balance
and proxy code are unchanged; the signing domain now includes the chain id.

Smoke tests on the upgraded Safe (simulated on top of the fork, not written to it):
receive and send ETH, add and remove an owner, ECDSA signature over the new domain, EIP-1271
through the new handler, module enable and execute, MultiSendCallOnly 1.5.0 batch, token
callbacks, rejection of old-domain approvals, and revert-on-inner-failure.

## Limits

- Mainnet only, 1.1.1 → 1.5.0 only.
- Existing modules, guards, nested Safes and dapp integrations are flagged, not exercised.
- The reference batch uses MultiSendCallOnly 1.3.0 as a stand-in; the UI may pick another
  official MultiSend deployment, which the checks accept.
- A transaction can only be rehearsed when its nonce is the Safe's current nonce.
- A fork of the latest block on a non-archive RPC goes stale after a while; restart rather
  than keeping one fork up for hours.

## Layout

- `safe-dryrun` — the CLI: picks the transaction, starts Anvil, runs the two phases, prints the verdict.
- `script/Execute.s.sol` — inspects the Safe, dissects the transaction, records the state diff, replays it on the fork.
- `script/Verify.s.sol` — post-upgrade comparison and smoke tests.
- `src/SafeConstants.sol` — canonical addresses, storage slots, EIP-712 type hashes.
