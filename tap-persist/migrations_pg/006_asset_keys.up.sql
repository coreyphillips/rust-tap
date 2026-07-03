-- PostgreSQL port of migrations/006_asset_keys.up.sql: key descriptors
-- and genesis metadata for owned assets. All columns are nullable:
-- rows written before this migration simply report NULL (None).

ALTER TABLE owned_assets ADD COLUMN script_key_family BIGINT;
ALTER TABLE owned_assets ADD COLUMN script_key_index BIGINT;
ALTER TABLE owned_assets ADD COLUMN script_key_raw BYTEA
    CHECK(script_key_raw IS NULL OR octet_length(script_key_raw) = 33);
ALTER TABLE owned_assets ADD COLUMN internal_key_family BIGINT;
ALTER TABLE owned_assets ADD COLUMN internal_key_index BIGINT;
ALTER TABLE owned_assets ADD COLUMN internal_key_raw BYTEA
    CHECK(internal_key_raw IS NULL OR octet_length(internal_key_raw) = 33);
ALTER TABLE owned_assets ADD COLUMN genesis_tag TEXT;
ALTER TABLE owned_assets ADD COLUMN genesis_meta_hash BYTEA
    CHECK(genesis_meta_hash IS NULL OR octet_length(genesis_meta_hash) = 32);
ALTER TABLE owned_assets ADD COLUMN genesis_output_index BIGINT;
ALTER TABLE owned_assets ADD COLUMN genesis_asset_type BIGINT;

INSERT INTO schema_version (version) VALUES (6);
