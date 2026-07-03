-- Pending anchor transactions awaiting confirmation. A node crash or
-- restart between broadcast and confirmation must not lose the context
-- needed to finish a mint (genesis proof generation and universe
-- registration) or a transfer (proof finishing, storage, and courier
-- delivery). One row per anchor transaction, keyed by the txid in
-- internal (little-endian) byte order. The payload is an opaque,
-- versioned blob whose encoding is owned by the embedding layer
-- (tap-node); `kind` discriminates mint (0) from transfer (1) anchors.
CREATE TABLE IF NOT EXISTS pending_anchors (
    txid BLOB PRIMARY KEY CHECK(length(txid) = 32),
    kind INTEGER NOT NULL,
    payload BLOB NOT NULL
);

INSERT INTO schema_version (version) VALUES (9);
