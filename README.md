# nockchain

Native Python tools for Nockchain wallet planning and transactions. Derive receiving
addresses, inspect payments, select coins, and sign single-key or multisig spends.
Python 3.11+; the package uses the standard library and has no runtime dependencies.

```sh
pip install nockchain
```

## Receive from a public branch

```python
from nockchain import derive_receive_address, parse_public_key

branch = parse_public_key(zpub)  # rejects private extended keys
receive = derive_receive_address(branch.zpub(), 42)
print(receive.address, receive.lock_root)
```

Reserve each receiving index durably before giving its address to a payer. Use a
dedicated non-hardened receiving branch and retain the path and allocated-index
range for recovery. `address` is the sending wallet's destination; `lock_root` is
its output lock commitment. A zpub is privacy-sensitive.

## Wallets and recovery

```python
from nockchain import generate_wallet, restore_wallet

key, recovery = generate_wallet("")  # optional BIP39 passphrase
# Back up recovery.words() privately before receiving funds. Never log it.
restored = restore_wallet(recovery.words(), "")
public_branch = key.derive("m/44'/0'/0'/9000").public().zpub()
```

`generate_mnemonic()` creates a 24-word English BIP39 phrase. Recovery accepts
12–24 words, validates checksums, and normalizes Unicode with NFKD. A wrong
passphrase produces a different valid wallet. `generate_seed()` creates a raw
64-byte seed; `master(seed_bytes)` accepts one. Raw seeds have no mnemonic.
`zprv()`, `words()`, and `Seed.to_bytes()` explicitly export spending authority.
Diagnostic string and repr output redact secret-bearing objects.

Paths start with `m` and are relative to the supplied key. Apostrophes mark
hardened indices, which require private parents. `public()` removes the private
scalar. Key parsing validates canonical coordinates and the Cheetah prime-order
subgroup.

## Exact amounts and coin selection

```python
from nockchain import Payment, parse_nocks, select_transfer

nicks = parse_nocks("1.25")  # 81920
plan = select_transfer(sender.public(), verified_unspent_notes, [
    Payment(destination, "1.25"),
])
review = plan.summary()
# Present the review and obtain the wallet user's authorization before signing.
signed = plan.sign(sender)
wire = signed.jam()
```

Amounts, heights, digest limbs, and atoms are Python integers. Floats and booleans
are rejected at numeric protocol boundaries. `1 NOCK = 65,536 nicks`;
`parse_nocks()` rejects sub-nick decimal precision, and `format_nocks()` is exact.

`select_transfer()` chooses sufficient notes largest-first with deterministic
note-name ties. `prepare_transfer()` consumes every supplied record. Both merge
repeated recipients, estimate fees, and send change to the sender unless
`TransferOptions(change_address=...)` is set. A nonzero `fee_nicks` supplies an
explicit fee. With automatic fees, a remainder too small to pay for change
metadata becomes part of the fee; the review shows the exact amount.
These helpers use the signing-key matcher; supply a chain context for mature coinbase inputs. `sign_transfer_v1()` accepts explicit
per-input output and fee allocations.

An `UnspentNote` holds the complete note and its verified lock root:

```python
from nockchain import NoteV1, NoteName, UnspentNote, cue, parse_digest

note = NoteV1(
    origin_page=100,
    name=NoteName(parse_digest(first), parse_digest(last)),
    note_data=cue(stored_metadata_jam),
    nicks=10_000_000,
)
unspent = UnspentNote(note, parse_digest(input_lock_root))
```

Parent commitments include version, origin, name, **all stored metadata**, and
value. Empty metadata is `0` only when the stored record actually has none.
The application authenticates input existence, unspent status, and confirmations.

## Pure planning and lock policies

```python
from nockchain import ChainContext, PlannedOutput, PlanRequest, SigningKeyLockMatcher, plan

result = plan(PlanRequest(
    candidates=tuple(verified_notes),
    outputs=(PlannedOutput.payment(recipient_pkh, 1_000_000),),
    refund=PlannedOutput(sender_lock.root, sender_lock.metadata(), 0),
    chain=ChainContext.at_height(chain_height),
), SigningKeyLockMatcher(sender_pkh))
review = result.transaction.summary()
# Review selected inputs, final_fee, minimum_fee, refunds, and word_counts.
signed = result.transaction.sign(sender)
```

Use `selection`, `order`, `fee_nicks`, or `sweep` in `PlanRequest` to control
selection and allocation. `LockRootLockMatcher` supplies `lock`, `leaf_number`,
`preimages`, and an optional `fund_policy`. `LockTreeV1`, `LockMerkleProof`, and
`build_lock_merkle_proof` expose the same policies at the transaction boundary.

The pure planner selects eligible notes, reserves a positive seed for every
input, assigns payments and refunds, and solves the fee from the encoded
transaction. Selection sorts by amount and then Base58 note name. An explicit
selection requires every chosen note to be eligible. A sweep consumes all
eligible candidates into one destination. An exact fee remains visible in the
review even when it is below the required minimum; signing rejects an underfunded
transaction.

The signing-key matcher handles single-signature PKH policies and the coinbase
relative-age policy. The root matcher selects a specific leaf of a disclosed
lock, checks hashlock preimages, and can use an explicitly configured fund root,
authoritative first name, and maturity policy. Fund maturity uses the candidate
height. Fee parameters independently select the fee schedule; the height helper
sets both together. With no candidate height, timed and fund inputs are ineligible.

Lock trees contain up to 16 leaves and pad to a power of two with burn conditions.
Leaf numbers start at 1. Conditions support PKH, timelock, hashlock, and burn
primitives; a burn condition cannot be spent. Proofs preserve the outer tree tag,
axis, and sibling path. Before Bythos, ordinary inputs use single-leaf stub proofs;
at Bythos they use full proofs. Refund metadata preserves the entire chosen
output policy, including trees and custom entries.

## Metadata, bridge payloads, and V0 migration

`NoteData` provides canonical metadata maps, hashing, word counts, and typed
`LockData`, `BridgeDepositDataPayload`, and `BridgeWithdrawalDataPayload` values.
Deposit addresses are exactly 20 big-endian bytes. Unknown versions and networks
remain raw nouns. `compute_bridge_fee` rounds up to whole NOCK before applying
the rate and saturates at uint64 limits. Construct an opaque output with a
`Digest` as `lock` and explicit `note_data`; full lock forms disclose their
metadata by default. Ethereum transaction construction and submission belong
to the caller.

`NoteV0.from_noun` reads complete V0 records, including public-key policy, source,
coinbase flag, and optional timelock. Set `version=0` in `PlanRequest` to migrate
those notes into V1 outputs. When parsing a migration transaction, supply
`migration_notes=verified_v0_notes, fees=fees` to `parse_transaction_v1`; the wire
witness does not contain the V0 input policy. Parent validation commits to the
complete supplied record. V0 and V1 candidates are selected separately.

## Multisig, timelocks, and independent signing

```python
from nockchain import (
    HeightRange, TimelockV1, LockV1, LockedPaymentV1, LockedSpendPlanV1,
    minimum_transaction_fee_v1, prepare_transaction_v1,
)

lock = LockV1(2, (alice_pkh, bob_pkh, carol_pkh), TimelockV1(
    relative=HeightRange(min=10),
    absolute=HeightRange(max=500_000),
))
fee = minimum_transaction_fee_v1([lock], [recipient_lock])
unsigned = prepare_transaction_v1([LockedSpendPlanV1(
    note=verified_note, lock=lock, fee=fee,
    outputs=(LockedPaymentV1(recipient_lock, verified_note.nicks - fee),),
)])
# Each signer independently reviews the same unsigned plan.
alice = unsigned.sign(alice_key)
bob = unsigned.sign(bob_key)
signed = alice.merge_signatures(bob)
signed.verify_signatures()
signed.validate_inputs([verified_note], chain_height)
```

A lock requires **exactly m signatures**, with up to 32 distinct keys. Extra
signatures are rejected. Timelock endpoints are inclusive; `None` is unbounded.
Relative heights measure age since the note's origin page. Signing does not
assert that a timelock is satisfied. Each signature changes the transaction ID.
Partial transactions travel as jam bytes; merging rejects altered plans and
conflicting signatures. Plans, notes, policies, and reviews are immutable.

## Inspect and validate

```python
from nockchain import parse_transaction_v1

tx = parse_transaction_v1(wire)
review = tx.summary()
tx.verify_signatures()
tx.validate_inputs(verified_notes, chain_height)
print(str(tx.id))
```

| Operation | What it establishes |
| --- | --- |
| `parse_transaction_v1()` | Supported structure, canonical trees, proof roots, key encoding, and embedded ID |
| `summary()` | Committed outputs, fees, signature hashes, and present signers |
| `OutputV1.lock()` | Metadata authenticates the committed output policy |
| `verify_signatures()` | Every signature, authorization, exact threshold, and minimum fee |
| `validate_inputs()` | Complete supplied records, parent hashes, balances, origin heights, and timelocks |

Validation methods raise `NockchainError` on protocol failures and return `None`
on success. `verify_digest()` returns a boolean. Successful parsing is not proof
of valid signatures or chain state. The package does not fetch chain data,
broadcast transactions, or implement confirmation policy.

## Protocol primitives and limits

`Digest` is an immutable tuple of five field elements. `str(digest)` encodes its
Base58 form and `parse_digest()` validates it. `Noun` is an integer atom or an
immutable `Cell`. Use `atom()`, `Cell(head, tail)`, `noun_tuple()`, and `noun_list()`
for construction; `hash_words()`, `hash_noun()`, `jam()`, and `cue()` implement the
hashing and codec primitives. Atom values must be below the Goldilocks prime;
these are based nouns, not arbitrary-size Nock atom containers.

Noun hashing and jam/cue traversal are iterative. Shared subtrees count toward
logical expansion limits even when backreferences make the wire encoding small.
Equality memoizes visited cell pairs. General noun operations allow 1,048,576
logical nodes and at most 16 MiB of jam bytes.

Transactions support V1 lock proofs and V0-to-V1 migration spends. Outputs have
unconstrained source fields.

Limits are 64 inputs, 256 output seeds, 32 keys per lock, 64 metadata entries,
2,048 flattened metadata words per output lock, 65,536 transaction nodes, and
depth 256. Every input retains at least one nonzero output seed.

Fee parameters control the phase height, base rate, witness divisor, and minimum.
At Bythos, metadata is merged per output lock and the witness discount applies.
Before Bythos, metadata is counted per seed and the base rate doubles. The default
fee context is height 54,000; provide the actual chain context when planning.
Conflicting metadata is rejected. Applications track network rule changes.

Private-key arithmetic is **variable-time**; use trusted offline signing tools.
See [SECURITY.md](SECURITY.md).

## Develop and verify

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
python -m unittest discover -s tests -v
ruff check src tests
ruff format --check src tests
python -m build
python -m twine check dist/*
```

The public corpus checks 35 wallet vectors, 105 signatures, 24 BIP39 vectors,
13 TIP5 vectors, seven noun encodings, four single-key transactions, and two
multisig transactions. Tests compare exact partial and signed bytes and the
canonical Hoon oracle's IDs, complete note commitments, and minimum fees.
Additional tests cover malformed input, immutable reviews, timelock boundaries,
metadata, fees, and selection. CI tests Python 3.11 and 3.13, then builds and
installs the wheel. Normal tests are offline and require no Go, Rust, or Hoon.

Wallet behavior is checked against the official Hoon source at
[`9bcc26c`](https://github.com/zorp-corp/nockchain/tree/9bcc26c6c57019dfde7f83aad9a9dd4ed5cd7902)
and the shared Rust wallet core at
[`02d1946`](https://github.com/SWPSCO/tx-types/tree/02d194605c475013745cc65b26f1413cd098932e).
The wallet corpus covers all 31 tagged lock leaves, metadata and bridge payloads,
phase-dependent fees, seven planner scenarios, and four V0 migration scenarios
with exact unsigned and signed bytes. Fixture files retain their source pins and
SHA-256 checksums. The Go repository contains the reproducible generators;
normal SDK tests use checked-in data and run offline.

**Never send funds to public test-vector addresses.**

MIT licensed. See [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) for wordlist attribution.
