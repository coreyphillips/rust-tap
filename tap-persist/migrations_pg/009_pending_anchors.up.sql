-- PostgreSQL port of migrations/009_pending_anchors.up.sql: pending
-- anchor transactions awaiting confirmation. One row per anchor
-- transaction, keyed by the txid in internal (little-endian) byte
-- order; `kind` discriminates mint (0) from transfer (1) anchors.

CREATE TABLE IF NOT EXISTS pending_anchors (
    txid BYTEA PRIMARY KEY CHECK(octet_length(txid) = 32),
    kind BIGINT NOT NULL,
    payload BYTEA NOT NULL
);

INSERT INTO schema_version (version) VALUES (9);
