-- PostgreSQL Row-Level Security (RLS) policies for ECDAT multi-tenancy.
-- Enforces complete tenant isolation: queries only see data where
-- tenant_id matches the session variable `app.current_tenant_id`.

DO $$
DECLARE
    tbl text;
    tables text[] := ARRAY[
        'repositories',
        'scans',
        'collector_runs',
        'assets',
        'occurrences',
        'evidence_records',
        'jobs',
        'risk_profiles',
        'risk_assessments',
        'policy_packs',
        'policy_results',
        'exemptions',
        'snapshots',
        'audit_events',
        'conflict_records'
    ];
BEGIN
    FOREACH tbl IN ARRAY tables LOOP
        -- Only proceed if table exists
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
            EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);

            EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_policy ON %I', tbl);
            EXECUTE format(
                'CREATE POLICY tenant_isolation_policy ON %I ' ||
                'FOR ALL ' ||
                'USING (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid) ' ||
                'WITH CHECK (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid)',
                tbl
            );
        END IF;
    END LOOP;
END $$;
