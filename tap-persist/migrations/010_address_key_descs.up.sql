-- Migration 010: wallet key descriptors for generated addresses.
--
-- An asset received on one of this node's addresses can only be sent
-- onward if the node can resolve the key descriptor (family, index,
-- raw public key) behind the address script key: the send path signs
-- through the AssetSigner seam using that descriptor. The address
-- table's script_key/internal_key columns hold the (possibly tweaked)
-- keys as they appear in the encoded address; these columns record the
-- raw wallet keys and their derivation coordinates. All columns are
-- nullable: rows written before this migration report NULL (no
-- descriptors known).

ALTER TABLE addresses ADD COLUMN script_key_family INTEGER;
ALTER TABLE addresses ADD COLUMN script_key_index INTEGER;
ALTER TABLE addresses ADD COLUMN script_key_raw BLOB
    CHECK(script_key_raw IS NULL OR length(script_key_raw) = 33);
ALTER TABLE addresses ADD COLUMN internal_key_family INTEGER;
ALTER TABLE addresses ADD COLUMN internal_key_index INTEGER;
ALTER TABLE addresses ADD COLUMN internal_key_raw BLOB
    CHECK(internal_key_raw IS NULL OR length(internal_key_raw) = 33);

INSERT INTO schema_version (version) VALUES (10);
