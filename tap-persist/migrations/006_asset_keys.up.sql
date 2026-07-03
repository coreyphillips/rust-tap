-- Migration 006: key descriptors and genesis metadata for owned assets.
--
-- Adds optional script key / internal key descriptors (family, index,
-- raw public key) and the genesis fields (tag, meta hash, output index,
-- asset type) needed to reconstruct an asset's Genesis alongside the
-- stored outpoint data. All columns are nullable: rows written before
-- this migration simply report NULL (None).

ALTER TABLE owned_assets ADD COLUMN script_key_family INTEGER;
ALTER TABLE owned_assets ADD COLUMN script_key_index INTEGER;
ALTER TABLE owned_assets ADD COLUMN script_key_raw BLOB
    CHECK(script_key_raw IS NULL OR length(script_key_raw) = 33);
ALTER TABLE owned_assets ADD COLUMN internal_key_family INTEGER;
ALTER TABLE owned_assets ADD COLUMN internal_key_index INTEGER;
ALTER TABLE owned_assets ADD COLUMN internal_key_raw BLOB
    CHECK(internal_key_raw IS NULL OR length(internal_key_raw) = 33);
ALTER TABLE owned_assets ADD COLUMN genesis_tag TEXT;
ALTER TABLE owned_assets ADD COLUMN genesis_meta_hash BLOB
    CHECK(genesis_meta_hash IS NULL OR length(genesis_meta_hash) = 32);
ALTER TABLE owned_assets ADD COLUMN genesis_output_index INTEGER;
ALTER TABLE owned_assets ADD COLUMN genesis_asset_type INTEGER;

INSERT INTO schema_version (version) VALUES (6);
