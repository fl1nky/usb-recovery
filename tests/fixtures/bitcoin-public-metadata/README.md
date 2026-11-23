# Wallet format controls

All three fixtures contain public format metadata only. Each is stored as Base64-encoded gzip for compactness. The test verifies the SHA256 of the uncompressed bytes.

- `core-bdb` and `other-bdb` were generated offline with the Bitcoin Core 27.2 Windows `bitcoin-wallet createfromdump` utility on regtest. Each dump had a single entry with five zero value bytes. The positive used the serialized public record name `bestblock`. The negative used `version` in the same BDB layout. The official ZIP SHA256 was `82e18f768aa5962b3c002d7f5d6ec9338896804f48406af4b5054c927575dbdf`. [Bitcoin Core distribution](https://bitcoincore.org/bin/bitcoin-core-27.2/)
- `core-schema` was created independently using Python's sqlite3, with mainnet application ID `0xf9beb4d9` and an empty table `main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)`. It tests schema recognition. [Bitcoin Core SQLite implementation](https://github.com/bitcoin/bitcoin/blob/master/src/wallet/sqlite.cpp)
