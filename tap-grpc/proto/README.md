# Vendored tapd protobuf definitions

These files are copied verbatim from the Go reference implementation at
`github.com/lightninglabs/taproot-assets` (v0.8.99-alpha), commit
`d82c7b4155ab0d8fec6cac302104f33e4afb95e9`:

- `tapcommon.proto` from `taprpc/tapcommon.proto`
- `taprootassets.proto` from `taprpc/taprootassets.proto`
- `universerpc/universe.proto` from `taprpc/universerpc/universe.proto`
- `authmailboxrpc/mailbox.proto` from `taprpc/authmailboxrpc/mailbox.proto`

This is the full import closure of the `universerpc.Universe` and
`authmailboxrpc.Mailbox` services: `universe.proto` imports
`tapcommon.proto` and `taprootassets.proto`; `mailbox.proto` and
`taprootassets.proto` import only `tapcommon.proto`. Imports are
resolved relative to this directory (matching the Go repo's `taprpc/`
root), so the build does not depend on a Go checkout.

Do not edit these files; re-vendor from the Go repo to update, and
record the new source commit here.
