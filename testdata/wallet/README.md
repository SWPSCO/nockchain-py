# Wallet reference fixtures

These public JAM fixtures come from the official Nockchain Hoon source at
`9bcc26c6c57019dfde7f83aad9a9dd4ed5cd7902`. Generation sources, source mappings,
and reproducible commands are in
[tx-types reference fixtures](https://github.com/SWPSCO/tx-types/tree/02d194605c475013745cc65b26f1413cd098932e/tx-types/tests/reference).

Run `sha256sum --check SHA256SUMS` in this directory to check the copied files.
The Hoon generators pad JAM atoms to eight-byte words; byte comparisons remove
only terminal zero padding. The fixture payloads contain public test values.

`reference.json` exposes the based-noun payloads and original Hoon oracle values.
It also includes seven pure-planner and four signed V0 migration scenarios from
the pinned Rust core. The reproducible exporter is in
[nockchain-go/testdata/wallet-generator](https://github.com/SWPSCO/nockchain-go/tree/main/testdata/wallet-generator).
Normal tests require no Rust or Hoon toolchain and run offline.
