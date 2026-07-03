-- PostgreSQL port of migrations/007_genesis_point.up.sql: genesis
-- outpoint for owned assets. Both columns are nullable: rows written
-- before this migration simply report NULL (None).

ALTER TABLE owned_assets ADD COLUMN genesis_point_txid BYTEA
    CHECK(genesis_point_txid IS NULL OR octet_length(genesis_point_txid) = 32);
ALTER TABLE owned_assets ADD COLUMN genesis_point_vout BIGINT;

INSERT INTO schema_version (version) VALUES (7);
