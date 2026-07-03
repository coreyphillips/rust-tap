-- PostgreSQL port of migrations/010_address_key_descs.up.sql: wallet
-- key descriptors for generated addresses. All columns are nullable:
-- rows written before this migration report NULL (no descriptors
-- known).

ALTER TABLE addresses ADD COLUMN script_key_family BIGINT;
ALTER TABLE addresses ADD COLUMN script_key_index BIGINT;
ALTER TABLE addresses ADD COLUMN script_key_raw BYTEA
    CHECK(script_key_raw IS NULL OR octet_length(script_key_raw) = 33);
ALTER TABLE addresses ADD COLUMN internal_key_family BIGINT;
ALTER TABLE addresses ADD COLUMN internal_key_index BIGINT;
ALTER TABLE addresses ADD COLUMN internal_key_raw BYTEA
    CHECK(internal_key_raw IS NULL OR octet_length(internal_key_raw) = 33);

INSERT INTO schema_version (version) VALUES (10);
