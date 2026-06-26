CREATE TABLE IF NOT EXISTS audit_ledger (
    seq            BIGSERIAL PRIMARY KEY,
    ts             timestamptz NOT NULL,
    actor          text NOT NULL,
    action         text NOT NULL,
    target         text,
    decision       text,
    rationale      text,
    evidence       jsonb,
    blast_radius   text,
    result         jsonb,
    policy_version text,
    model_version  text,
    prev_hash      text NOT NULL,
    entry_hash     text NOT NULL
);

CREATE OR REPLACE FUNCTION audit_ledger_no_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_ledger is append-only: % on seq % rejected',
        TG_OP, OLD.seq;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_ledger_append_only ON audit_ledger;
CREATE TRIGGER audit_ledger_append_only
    BEFORE UPDATE OR DELETE ON audit_ledger
    FOR EACH ROW EXECUTE FUNCTION audit_ledger_no_mutate();
