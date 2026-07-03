-- PostgreSQL port of migrations/008_multi_asset_anchor.up.sql: allow
-- multiple assets per anchor outpoint.
--
-- SQLite cannot alter a UNIQUE constraint in place, so the original
-- migration rebuilds the whole owned_assets table. PostgreSQL can swap
-- the constraint directly (it was given an explicit name in the ported
-- migration 001 for exactly this purpose), preserving rows, ids, and
-- the id sequence.

ALTER TABLE owned_assets DROP CONSTRAINT owned_assets_anchor_unique;
ALTER TABLE owned_assets ADD CONSTRAINT owned_assets_anchor_unique
    UNIQUE(anchor_txid, anchor_vout, asset_id, script_key);

INSERT INTO schema_version (version) VALUES (8);
