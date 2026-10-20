# Security

Online services use a dedicated public receiving branch. Public extended keys
are privacy-sensitive. A non-hardened child private key together with its parent
zpub can expose the parent's private key.

Cheetah arithmetic uses variable-time Python integer operations. Private
operations belong in trusted offline wallet tools, not remote signing or key
services. Python's allocator and garbage collector do not guarantee erasure of
secret copies. `zprv()`, `words()`, and `Seed.to_bytes()` explicitly export spending
authority. Diagnostic string/repr output is redacted; generic object serializers
and private attributes are not secret-storage boundaries. Callers own logging,
backups, storage, and access control.

Nouns, locks, notes and transaction reviews are immutable. Decoding has byte,
logical-node and depth limits. Parsing does not establish signature or chain
validity. Call `verify_signatures()` and `validate_inputs()` explicitly; obtain
complete input records, canonical height, unspent status, and confirmations from
a trusted chain-state source.

V1 condition trees and V0 migration inputs are supported. Fund inputs require an
explicit authoritative identity and maturity policy. Migration parsing requires
complete V0 records. Bridge payload codecs do not establish cross-chain finality
or submit Ethereum transactions. This package is not a full consensus validator,
chain client, or broadcaster. Applications supply correct height and fee contexts.
Native NOCK uses nicks (2^16 per NOCK), distinct from Base ERC-20 units.

Tests use public Hoon, Rust and BIP39 fixtures. No independent cryptographic audit
is claimed. Report vulnerabilities privately through GitHub private reporting
when available or another established private channel to the maintainers. Never
include real seeds, private extended keys, API credentials, or identifying wallet
data in issues or reproductions.
