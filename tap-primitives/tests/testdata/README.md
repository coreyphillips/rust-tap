# Vendored test vectors

The files in this directory are verbatim copies of the BIP test vectors
from the Lightning Labs Taproot Assets reference implementation:

- Source: https://github.com/lightninglabs/taproot-assets
- Version: v0.8.99-alpha main branch, commit d82c7b4155ab0d8fec6cac302104f33e4afb95e9

Original locations:

- `asset_tlv_encoding_generated.json`, `asset_tlv_encoding_error_cases.json`,
  `asset.hex`: `asset/testdata/`
- `address_tlv_encoding_generated.json`, `address_tlv_encoding_error_cases.json`:
  `address/testdata/`
- `mssmt_tree_proofs.json`, `mssmt_tree_deletion.json`,
  `mssmt_tree_replacement.json`, `mssmt_tree_error_cases.json`:
  `mssmt/testdata/`
- `proof_tlv_encoding_generated.json`, `proof_tlv_encoding_error_cases.json`,
  `proof_tlv_encoding_regtest.json`, `proof.hex`, `proof-file.hex`,
  `ownership-proof.hex`: `proof/testdata/`

Do NOT edit these files. They are the acceptance gate for wire-format
compatibility: encoded bytes produced by this crate must be identical to
the `expected` values, and decoding the `expected` values followed by
re-encoding must round-trip byte-exactly.
