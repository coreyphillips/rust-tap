-- Migration 007: genesis outpoint for owned assets.
--
-- Adds the genesis outpoint (Genesis.first_prev_out: the first input
-- of the genesis transaction, in internal byte order, plus its vout)
-- so a full `Genesis` can be reconstructed from a stored asset. Both
-- columns are nullable: rows written before this migration simply
-- report NULL (None).

ALTER TABLE owned_assets ADD COLUMN genesis_point_txid BLOB
    CHECK(genesis_point_txid IS NULL OR length(genesis_point_txid) = 32);
ALTER TABLE owned_assets ADD COLUMN genesis_point_vout INTEGER;

INSERT INTO schema_version (version) VALUES (7);
