--
-- PostgreSQL database dump
--

\restrict fJgN805giwJxgbfBie5ATfa8e5igAFbJjdQ6ZVBIIePx3KySxvtDIhr0JIbqT0K

-- Dumped from database version 16.15
-- Dumped by pg_dump version 16.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: advisoryconfidence; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.advisoryconfidence AS ENUM (
    'HIGH',
    'MEDIUM',
    'LOW'
);


ALTER TYPE public.advisoryconfidence OWNER TO ecdat;

--
-- Name: analysisstatus; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.analysisstatus AS ENUM (
    'OBSERVED',
    'NOT_OBSERVED',
    'UNKNOWN',
    'INDETERMINATE',
    'UNSUPPORTED',
    'observed',
    'not_observed',
    'unknown',
    'indeterminate',
    'unsupported'
);


ALTER TYPE public.analysisstatus OWNER TO ecdat;

--
-- Name: collectorstatus; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.collectorstatus AS ENUM (
    'SUCCESS',
    'PARTIAL',
    'FAILED',
    'UNSUPPORTED',
    'SKIPPED',
    'success',
    'partial',
    'failed',
    'unsupported',
    'skipped'
);


ALTER TYPE public.collectorstatus OWNER TO ecdat;

--
-- Name: confidence; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.confidence AS ENUM (
    'CONFIRMED',
    'PROBABLE',
    'UNCONFIRMED',
    'confirmed',
    'probable',
    'unconfirmed'
);


ALTER TYPE public.confidence OWNER TO ecdat;

--
-- Name: conflictresolutionstate; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.conflictresolutionstate AS ENUM (
    'UNRESOLVED',
    'RESOLVED',
    'ACCEPTED_CONFLICT'
);


ALTER TYPE public.conflictresolutionstate OWNER TO ecdat;

--
-- Name: criticality; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.criticality AS ENUM (
    'CRITICAL',
    'HIGH',
    'MEDIUM',
    'LOW'
);


ALTER TYPE public.criticality OWNER TO ecdat;

--
-- Name: dependencyevidencelevel; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.dependencyevidencelevel AS ENUM (
    'CAPABILITY',
    'IMPORT',
    'STATIC_USE',
    'RUNTIME_USE',
    'UNKNOWN'
);


ALTER TYPE public.dependencyevidencelevel OWNER TO ecdat;

--
-- Name: errorclass; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.errorclass AS ENUM (
    'RETRYABLE',
    'NON_RETRYABLE',
    'SECURITY',
    'CONFIGURATION',
    'UNSUPPORTED'
);


ALTER TYPE public.errorclass OWNER TO ecdat;

--
-- Name: exposureclass; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.exposureclass AS ENUM (
    'INTERNAL',
    'EXTERNAL',
    'DMZ',
    'UNKNOWN'
);


ALTER TYPE public.exposureclass OWNER TO ecdat;

--
-- Name: jobstate; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.jobstate AS ENUM (
    'QUEUED',
    'CLAIMED',
    'RUNNING',
    'SUCCEEDED',
    'FAILED_RETRYABLE',
    'FAILED_FINAL',
    'CANCELLED',
    'EXPIRED',
    'queued',
    'claimed',
    'running',
    'succeeded',
    'failed_retryable',
    'failed_final',
    'cancelled',
    'expired'
);


ALTER TYPE public.jobstate OWNER TO ecdat;

--
-- Name: jobtype; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.jobtype AS ENUM (
    'SCAN_CREATE',
    'COLLECT_SOURCE',
    'COLLECT_DEPENDENCY',
    'COLLECT_CONTAINER',
    'NORMALIZE',
    'CORRELATE',
    'CALCULATE_RISK',
    'EVALUATE_POLICY',
    'GENERATE_ADVISORY',
    'GENERATE_CBOM',
    'CREATE_SNAPSHOT',
    'TIMESTAMP_SNAPSHOT',
    'GENERATE_EXPORT',
    'scan_create',
    'collect_source',
    'collect_dependency',
    'collect_container',
    'normalize',
    'correlate',
    'calculate_risk',
    'evaluate_policy',
    'generate_advisory',
    'generate_cbom',
    'create_snapshot',
    'timestamp_snapshot',
    'generate_export'
);


ALTER TYPE public.jobtype OWNER TO ecdat;

--
-- Name: matchtype; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.matchtype AS ENUM (
    'STABLE_EXTERNAL_ID',
    'CERTIFICATE_FINGERPRINT',
    'PACKAGE_COORDINATES',
    'REPO_PATH_SEMANTIC',
    'NORMALIZED_OBSERVATION',
    'NEW_ASSET',
    'POSSIBLE_DUPLICATE',
    'stable_external_id',
    'certificate_fingerprint',
    'package_coordinates',
    'repo_path_semantic',
    'normalized_observation',
    'new_asset',
    'possible_duplicate'
);


ALTER TYPE public.matchtype OWNER TO ecdat;

--
-- Name: observationtype; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.observationtype AS ENUM (
    'ALGORITHM_USE',
    'KEY_GENERATION',
    'SIGNING',
    'VERIFICATION',
    'ENCRYPTION',
    'DECRYPTION',
    'HASHING',
    'KEY_AGREEMENT',
    'KEY_DERIVATION',
    'RANDOM_GENERATION',
    'CERTIFICATE_OPERATION',
    'HARDCODED_MATERIAL',
    'algorithm_use',
    'key_generation',
    'signing',
    'verification',
    'encryption',
    'decryption',
    'hashing',
    'key_agreement',
    'key_derivation',
    'random_generation',
    'certificate_operation',
    'hardcoded_material'
);


ALTER TYPE public.observationtype OWNER TO ecdat;

--
-- Name: policypackstatus; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.policypackstatus AS ENUM (
    'DRAFT',
    'REVIEW',
    'ACTIVE',
    'SUPERSEDED',
    'RETIRED',
    'active',
    'draft',
    'review',
    'superseded',
    'retired'
);


ALTER TYPE public.policypackstatus OWNER TO ecdat;

--
-- Name: policyverdict; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.policyverdict AS ENUM (
    'PASS',
    'FAIL',
    'WARN',
    'NOT_APPLICABLE',
    'pass',
    'fail',
    'warn',
    'exempt'
);


ALTER TYPE public.policyverdict OWNER TO ecdat;

--
-- Name: relationshiptype; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.relationshiptype AS ENUM (
    'IMPLEMENTS',
    'USES',
    'DEPENDS_ON',
    'CONTAINS',
    'OBSERVED_ON',
    'DERIVED_FROM'
);


ALTER TYPE public.relationshiptype OWNER TO ecdat;

--
-- Name: scanstatus; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.scanstatus AS ENUM (
    'QUEUED',
    'RUNNING',
    'COMPLETE',
    'PARTIAL',
    'FAILED',
    'CANCELLED',
    'queued',
    'running',
    'complete',
    'partial',
    'failed',
    'cancelled'
);


ALTER TYPE public.scanstatus OWNER TO ecdat;

--
-- Name: standardstatus; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.standardstatus AS ENUM (
    'FINAL',
    'DRAFT',
    'SELECTED_NOT_FINAL',
    'DEPRECATED',
    'EXPERIMENTAL'
);


ALTER TYPE public.standardstatus OWNER TO ecdat;

--
-- Name: usageevidence; Type: TYPE; Schema: public; Owner: ecdat
--

CREATE TYPE public.usageevidence AS ENUM (
    'STATIC',
    'DYNAMIC',
    'INFERRED',
    'UNKNOWN',
    'static',
    'dynamic',
    'inferred'
);


ALTER TYPE public.usageevidence OWNER TO ecdat;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: advisory_families; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.advisory_families (
    name character varying(200) NOT NULL,
    fips_number character varying(50),
    use_cases jsonb NOT NULL,
    standard_status public.standardstatus NOT NULL,
    production_recommended boolean NOT NULL,
    description text,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.advisory_families OWNER TO ecdat;

--
-- Name: advisory_mappings; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.advisory_mappings (
    from_primitive character varying(200) NOT NULL,
    from_use_case character varying(200) NOT NULL,
    to_family_id uuid NOT NULL,
    to_variant_id uuid,
    is_hybrid boolean NOT NULL,
    hybrid_classical_component character varying(200),
    priority integer NOT NULL,
    notes text,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.advisory_mappings OWNER TO ecdat;

--
-- Name: advisory_variants; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.advisory_variants (
    family_id uuid NOT NULL,
    name character varying(200) NOT NULL,
    parameter_set character varying(100) NOT NULL,
    nist_security_level integer,
    public_key_bytes integer,
    secret_key_bytes integer,
    ciphertext_bytes integer,
    signature_bytes integer,
    latency_class character varying(50),
    advisory_confidence public.advisoryconfidence NOT NULL,
    standard_status public.standardstatus NOT NULL,
    production_recommended boolean NOT NULL,
    source_reference character varying(1000),
    transition_guidance text,
    notes text,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.advisory_variants OWNER TO ecdat;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO ecdat;

--
-- Name: assets; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.assets (
    tenant_id uuid NOT NULL,
    stable_id character varying(500) NOT NULL,
    match_type public.matchtype NOT NULL,
    asset_type character varying(100) NOT NULL,
    algorithm character varying(200),
    algorithm_normalized character varying(200),
    key_size integer,
    curve character varying(100),
    provider character varying(200),
    operation character varying(100),
    confidence public.confidence NOT NULL,
    analysis_status public.analysisstatus NOT NULL,
    analysis_reason character varying(500),
    usage_evidence public.usageevidence NOT NULL,
    has_conflict boolean NOT NULL,
    extra jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.assets OWNER TO ecdat;

--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.audit_events (
    tenant_id uuid NOT NULL,
    event_type character varying(100) NOT NULL,
    actor_id character varying(255),
    actor_role character varying(50),
    resource_type character varying(100),
    resource_id uuid,
    detail jsonb NOT NULL,
    ip_address character varying(50),
    user_agent character varying(500),
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.audit_events OWNER TO ecdat;

--
-- Name: collector_runs; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.collector_runs (
    tenant_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    collector_name character varying(100) NOT NULL,
    collector_version character varying(50) NOT NULL,
    status public.collectorstatus NOT NULL,
    is_required boolean NOT NULL,
    findings_count integer NOT NULL,
    error_message text,
    error_code character varying(100),
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    raw_output_uri character varying(2000),
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.collector_runs OWNER TO ecdat;

--
-- Name: components; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.components (
    tenant_id uuid NOT NULL,
    name character varying(500) NOT NULL,
    component_type character varying(100) NOT NULL,
    purl character varying(1000),
    version character varying(200),
    criticality public.criticality NOT NULL,
    exposure public.exposureclass NOT NULL,
    extra jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.components OWNER TO ecdat;

--
-- Name: conflict_records; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.conflict_records (
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    evidence_ids jsonb NOT NULL,
    conflict_type character varying(100) NOT NULL,
    resolution_state public.conflictresolutionstate NOT NULL,
    resolution_reason text,
    resolved_by character varying(255),
    resolved_at timestamp with time zone,
    raw_detail jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.conflict_records OWNER TO ecdat;

--
-- Name: dead_letter_events; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.dead_letter_events (
    job_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    scan_id uuid,
    job_type public.jobtype NOT NULL,
    total_attempts integer NOT NULL,
    last_error text,
    last_worker character varying(255),
    input_hash character varying(255),
    payload jsonb NOT NULL,
    resolved boolean DEFAULT false NOT NULL,
    resolved_by character varying(255),
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.dead_letter_events OWNER TO ecdat;

--
-- Name: evidence; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.evidence (
    tenant_id uuid NOT NULL,
    occurrence_id uuid NOT NULL,
    content_hash character varying(255) NOT NULL,
    content_type character varying(100) NOT NULL,
    size_bytes integer NOT NULL,
    storage_uri character varying(2000),
    inline_content jsonb,
    retention_until character varying(50),
    retention_hold boolean NOT NULL,
    collector_name character varying(100) NOT NULL,
    collector_version character varying(50) NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.evidence OWNER TO ecdat;

--
-- Name: exemptions; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.exemptions (
    tenant_id uuid NOT NULL,
    policy_result_id uuid,
    rule_id character varying(100) NOT NULL,
    asset_id uuid,
    scope character varying(500),
    reason text NOT NULL,
    owner character varying(255) NOT NULL,
    approver character varying(255),
    expires_at timestamp with time zone NOT NULL,
    is_active boolean NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.exemptions OWNER TO ecdat;

--
-- Name: job_attempts; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.job_attempts (
    job_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    worker_id character varying(255) NOT NULL,
    state public.jobstate NOT NULL,
    started_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    error_code character varying(100),
    error_message text,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.job_attempts OWNER TO ecdat;

--
-- Name: job_events; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.job_events (
    job_id uuid NOT NULL,
    event_type character varying(100) NOT NULL,
    old_state public.jobstate,
    new_state public.jobstate,
    worker_id character varying(255),
    detail jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.job_events OWNER TO ecdat;

--
-- Name: jobs; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.jobs (
    tenant_id uuid NOT NULL,
    scan_id uuid,
    job_type public.jobtype NOT NULL,
    state public.jobstate NOT NULL,
    priority integer NOT NULL,
    idempotency_key character varying(500) NOT NULL,
    attempt integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 5 NOT NULL,
    scheduled_at timestamp with time zone,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    lease_until timestamp with time zone,
    worker_id character varying(255),
    error_code character varying(100),
    error_class public.errorclass,
    error_message text,
    input_hash character varying(255),
    payload jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.jobs OWNER TO ecdat;

--
-- Name: occurrences; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.occurrences (
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    scan_id uuid,
    collector_run_id uuid,
    location_type character varying(50) NOT NULL,
    repository character varying(2000),
    file_path character varying(2000),
    line integer,
    "column" integer,
    commit_ref character varying(255),
    image_digest character varying(255),
    layer_digest character varying(255),
    observation_type public.observationtype,
    dependency_evidence_level public.dependencyevidencelevel,
    detection_rule_id character varying(100),
    detection_rule_version character varying(50),
    collector_name character varying(100) NOT NULL,
    collector_version character varying(50) NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.occurrences OWNER TO ecdat;

--
-- Name: policy_packs; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.policy_packs (
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    version character varying(100) NOT NULL,
    status public.policypackstatus NOT NULL,
    source_document character varying(500),
    source_version character varying(100),
    published_at timestamp with time zone,
    effective_from timestamp with time zone,
    effective_until timestamp with time zone,
    jurisdiction character varying(200),
    checksum character varying(255),
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.policy_packs OWNER TO ecdat;

--
-- Name: policy_results; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.policy_results (
    tenant_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    policy_pack_id uuid NOT NULL,
    policy_pack_version character varying(100) NOT NULL,
    rule_id character varying(100) NOT NULL,
    verdict public.policyverdict NOT NULL,
    offending_property character varying(200),
    offending_value character varying(500),
    explanation text,
    source_reference character varying(1000),
    opa_input_hash character varying(255),
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.policy_results OWNER TO ecdat;

--
-- Name: policy_rules; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.policy_rules (
    pack_id uuid NOT NULL,
    rule_id character varying(100) NOT NULL,
    version character varying(50) NOT NULL,
    name character varying(500) NOT NULL,
    description text,
    severity character varying(50) NOT NULL,
    rego_package character varying(500),
    source_reference character varying(1000),
    conditions jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.policy_rules OWNER TO ecdat;

--
-- Name: relationships; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.relationships (
    tenant_id uuid NOT NULL,
    relationship_type public.relationshiptype NOT NULL,
    from_id uuid NOT NULL,
    from_type character varying(50) NOT NULL,
    to_id uuid NOT NULL,
    to_type character varying(50) NOT NULL,
    metadata jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.relationships OWNER TO ecdat;

--
-- Name: repositories; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.repositories (
    tenant_id uuid NOT NULL,
    name character varying(500) NOT NULL,
    url character varying(2000),
    vcs_type character varying(50),
    default_branch character varying(255),
    language character varying(100),
    metadata jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.repositories OWNER TO ecdat;

--
-- Name: risk_assessments; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.risk_assessments (
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    risk_profile_id uuid NOT NULL,
    risk_profile_version character varying(100) NOT NULL,
    x_value double precision,
    x_source character varying(255),
    x_source_version character varying(50),
    x_override boolean NOT NULL,
    y_value double precision,
    y_min double precision,
    y_max double precision,
    y_source character varying(255),
    y_assumption text,
    mosca_results jsonb NOT NULL,
    qars_temporal double precision,
    qars_sensitivity double precision,
    qars_exposure double precision,
    qars_score double precision,
    original_qars_score double precision,
    override_score double precision,
    override_reason text,
    override_reviewer character varying(255),
    override_at timestamp with time zone,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.risk_assessments OWNER TO ecdat;

--
-- Name: risk_profiles; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.risk_profiles (
    tenant_id uuid NOT NULL,
    version character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    is_active boolean NOT NULL,
    weight_temporal double precision NOT NULL,
    weight_sensitivity double precision NOT NULL,
    weight_exposure double precision NOT NULL,
    x_default_years double precision,
    y_default_years double precision,
    metadata jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.risk_profiles OWNER TO ecdat;

--
-- Name: scans; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.scans (
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    commit_ref character varying(255),
    input_revision character varying(255),
    status public.scanstatus NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    canonical_model_version character varying(50) NOT NULL,
    scan_configuration jsonb NOT NULL,
    is_complete boolean NOT NULL,
    completeness_summary jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.scans OWNER TO ecdat;

--
-- Name: snapshots; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.snapshots (
    tenant_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    canonical_hash character varying(255) NOT NULL,
    merkle_root character varying(255) NOT NULL,
    tsa_url character varying(2000),
    tsa_timestamp_at timestamp with time zone,
    tsa_token_hash character varying(255),
    tsa_token_uri character varying(2000),
    canonical_model_version character varying(50) NOT NULL,
    policy_pack_versions jsonb NOT NULL,
    risk_profile_version character varying(100),
    advisory_version character varying(100),
    merkle_tree_uri character varying(2000),
    is_verified boolean NOT NULL,
    verified_at timestamp with time zone,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.snapshots OWNER TO ecdat;

--
-- Name: tenants; Type: TABLE; Schema: public; Owner: ecdat
--

CREATE TABLE public.tenants (
    name character varying(255) NOT NULL,
    display_name character varying(500) NOT NULL,
    is_active boolean NOT NULL,
    settings jsonb NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.tenants OWNER TO ecdat;

--
-- Data for Name: advisory_families; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.advisory_families (name, fips_number, use_cases, standard_status, production_recommended, description, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: advisory_mappings; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.advisory_mappings (from_primitive, from_use_case, to_family_id, to_variant_id, is_hybrid, hybrid_classical_component, priority, notes, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: advisory_variants; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.advisory_variants (family_id, name, parameter_set, nist_security_level, public_key_bytes, secret_key_bytes, ciphertext_bytes, signature_bytes, latency_class, advisory_confidence, standard_status, production_recommended, source_reference, transition_guidance, notes, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.alembic_version (version_num) FROM stdin;
5c9c9631e9f1
\.


--
-- Data for Name: assets; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.assets (tenant_id, stable_id, match_type, asset_type, algorithm, algorithm_normalized, key_size, curve, provider, operation, confidence, analysis_status, analysis_reason, usage_evidence, has_conflict, extra, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	sha256:cfcf3a0c8300bc73450f412bfc354b4eb26fca39ddc0714770e6e714e3589638	repo_path_semantic	algorithm	SHA256withRSA	SHA256withRSA	\N	\N	\N	\N	probable	observed	\N	static	f	{"curve": null, "key_size": null, "provider": null, "operation": null}	514541ce-a2e7-41d7-9e66-152e3d63da8a	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	sha256:49454f97f5048cca01df8b4ae5dd7c81f08a4d93990fbe4002c625e06afd3537	repo_path_semantic	algorithm	DESede/CBC/PKCS5Padding	3DES	\N	\N	\N	\N	confirmed	observed	\N	static	f	{"curve": null, "key_size": null, "provider": null, "operation": null}	b0d8844a-aec9-47a8-b526-a242718ab205	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	sha256:6e1312395b4030210127fc856c4744d3c43172bcc96f393f742356a3f8ef7168	repo_path_semantic	algorithm	RSA	RSA	\N	\N	\N	\N	confirmed	observed	\N	static	f	{"curve": null, "key_size": null, "provider": null, "operation": null, "pqc_advisory": {"urgency": "RSA signatures are broken by Shor's. Migrate to ML-DSA or SLH-DSA.", "standard": "FIPS 204", "recommended": "ML-DSA-65", "cnsa2_compliant": true, "migration_effort": "high"}}	5150438b-3602-4908-8dc5-d5c154592a00	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
\.


--
-- Data for Name: audit_events; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.audit_events (tenant_id, event_type, actor_id, actor_role, resource_type, resource_id, detail, ip_address, user_agent, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: collector_runs; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.collector_runs (tenant_id, scan_id, collector_name, collector_version, status, is_required, findings_count, error_message, error_code, started_at, completed_at, raw_output_uri, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	source-scanner	1.0.0	SUCCESS	t	3	\N	\N	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00	\N	4ab5ffe1-41d9-49e6-8a6b-118b8dd02196	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	source-scanner	1.0.0	SUCCESS	t	3	\N	\N	2026-09-22 04:14:38.375723+00	2026-09-22 04:14:38.375723+00	\N	a0e01229-164c-4d88-bff0-bece50b43de0	2026-09-22 04:14:38.375723+00	2026-09-22 04:14:38.375723+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	source-scanner	1.0.0	SUCCESS	t	3	\N	\N	2026-09-22 04:17:03.780453+00	2026-09-22 04:17:03.780453+00	\N	a42a2425-bb2f-4653-b5a9-50a291aae70e	2026-09-22 04:17:03.780453+00	2026-09-22 04:17:03.780453+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	source-scanner	1.0.0	SUCCESS	t	3	\N	\N	2026-09-22 16:42:36.36347+00	2026-09-22 16:42:36.36347+00	\N	52a9d485-59e3-44a6-90cc-f731294ede20	2026-09-22 16:42:36.36347+00	2026-09-22 16:42:36.36347+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	source-scanner	1.0.0	SUCCESS	t	3	\N	\N	2026-09-22 16:44:03.760989+00	2026-09-22 16:44:03.760989+00	\N	e93835d4-a782-432b-b59e-1335988c5413	2026-09-22 16:44:03.760989+00	2026-09-22 16:44:03.760989+00
\.


--
-- Data for Name: components; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.components (tenant_id, name, component_type, purl, version, criticality, exposure, extra, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: conflict_records; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.conflict_records (tenant_id, asset_id, evidence_ids, conflict_type, resolution_state, resolution_reason, resolved_by, resolved_at, raw_detail, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: dead_letter_events; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.dead_letter_events (job_id, tenant_id, scan_id, job_type, total_attempts, last_error, last_worker, input_hash, payload, resolved, resolved_by, id, created_at, updated_at) FROM stdin;
e38f7754-f49a-4972-a681-dfb8abbcd806	19e7e44b-6d63-4c16-9ef7-701b266550a7	c51fe79c-a401-4d54-8001-456d65442e98	collect_source	2	'EvidenceEnvelope' object has no attribute 'rule'	worker-66-47c11e26	\N	{"scan_id": "c51fe79c-a401-4d54-8001-456d65442e98", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	f	\N	58feba39-044b-4c9c-878e-1a68f716c764	2026-09-22 03:56:14.910855+00	2026-09-22 03:56:14.910855+00
a2f55c86-a233-4b4d-be80-410c9b263081	19e7e44b-6d63-4c16-9ef7-701b266550a7	a1b341a0-deb5-450e-b363-066fed45ef60	collect_source	2	'EvidenceEnvelope' object has no attribute 'rule'	worker-66-47c11e26	\N	{"scan_id": "a1b341a0-deb5-450e-b363-066fed45ef60", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	f	\N	6a70473c-c213-434e-8270-fbc79e38c741	2026-09-22 03:56:14.911529+00	2026-09-22 03:56:14.911529+00
af3f5778-98a0-46e8-948c-3332e74b9ecf	19e7e44b-6d63-4c16-9ef7-701b266550a7	9f008610-d735-47d9-80a3-3a52020c90f0	collect_source	2	'EvidenceEnvelope' object has no attribute 'rule'	worker-66-47c11e26	\N	{"scan_id": "9f008610-d735-47d9-80a3-3a52020c90f0", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	f	\N	fd1b8eac-f958-4768-a1f3-e5944e617eec	2026-09-22 03:56:14.939442+00	2026-09-22 03:56:14.939442+00
e0e05b21-1f36-423c-8fdb-081679af4333	19e7e44b-6d63-4c16-9ef7-701b266550a7	024b13c4-3c2b-41bb-aa55-502939749cb0	collect_source	2	(sqlalchemy.dialects.postgresql.asyncpg.ProgrammingError) <class 'asyncpg.exceptions.InvalidColumnReferenceError'>: there is no unique or exclusion constraint matching the ON CONFLICT specification\n[SQL: \n                    INSERT INTO assets (id, tenant_id, stable_id, match_type, asset_type, algorithm,\n                                        algorithm_normalized, key_size, curve, provider, operation,\n                                        confidence, analysis_status, usage_evidence,\n                                        has_conflict, extra)\n                    VALUES (gen_random_uuid(), $1, $2, $3, $4,\n                            $5, $6, $7, $8, $9, $10,\n                            $11, $12, $13,\n                            false, $14)\n                    ON CONFLICT (stable_id) DO UPDATE SET\n                        algorithm = EXCLUDED.algorithm,\n                        algorithm_normalized = EXCLUDED.algorithm_normalized,\n                        confidence = EXCLUDED.confidence,\n                        extra = EXCLUDED.extra\n                    RETURNING id\n                ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', 'sha256:6e1312395b4030210127fc856c4744d3c43172bcc96f393f742356a3f8ef7168', 'repo_path_semantic', 'algorithm', 'RSA', 'RSA', None, None, None, None, 'confirmed', 'observed', 'static', '{"key_size": null, "curve": null, "provider": null, "operation": null}')]\n(Background on this error at: https://sqlalche.me/e/20/f405)	worker-66-f3503e02	\N	{"scan_id": "024b13c4-3c2b-41bb-aa55-502939749cb0", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	f	\N	7cf09f90-6222-400e-8bdd-97431f3a2db8	2026-09-22 04:08:24.997511+00	2026-09-22 04:08:24.997511+00
accf317d-42bf-4d7b-a695-963991e7d67d	19e7e44b-6d63-4c16-9ef7-701b266550a7	55b8a79d-a57c-4410-82fd-dcf19e933127	collect_source	2	(sqlalchemy.dialects.postgresql.asyncpg.ProgrammingError) <class 'asyncpg.exceptions.PostgresSyntaxError'>: syntax error at or near "column"\n[SQL: \n                    INSERT INTO occurrences (\n                        id, tenant_id, asset_id, scan_id, collector_run_id,\n                        location_type, repository, file_path, line, column,\n                        commit_ref, observation_type, detection_rule_id, detection_rule_version,\n                        collector_name, collector_version, created_at, updated_at\n                    ) VALUES (\n                        gen_random_uuid(), $1, $2, $3, $4,\n                        'source', $5, $6, $7, $8,\n                        $9, $10, $11, $12,\n                        $13, $14, NOW(), NOW()\n                    )\n                ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', 'ae5ea825-7b20-4889-9b7e-87ca4a19c634', '55b8a79d-a57c-4410-82fd-dcf19e933127', 'accf317d-42bf-4d7b-a695-963991e7d67d', 'payment-gateway-service', 'PaymentService.java', 15, None, 'main', 'key_generation', 'JAVA-RSA-001', '1.0', 'java-source', '1.0.0')]\n(Background on this error at: https://sqlalche.me/e/20/f405)	worker-45-aac7fee1	\N	{"scan_id": "55b8a79d-a57c-4410-82fd-dcf19e933127", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	f	\N	fef57347-1857-4a52-a4cf-33bf1c75a154	2026-09-22 04:09:40.042559+00	2026-09-22 04:09:40.042559+00
9e5368e1-5c00-4c64-a4b6-acf5f6ba5d11	19e7e44b-6d63-4c16-9ef7-701b266550a7	96294047-e987-41b3-9237-686a7f32368c	collect_source	2	(sqlalchemy.dialects.postgresql.asyncpg.ProgrammingError) <class 'asyncpg.exceptions.PostgresSyntaxError'>: syntax error at or near "column"\n[SQL: \n                    INSERT INTO occurrences (\n                        id, tenant_id, asset_id, scan_id, collector_run_id,\n                        location_type, repository, file_path, line, column,\n                        commit_ref, observation_type, detection_rule_id, detection_rule_version,\n                        collector_name, collector_version, created_at, updated_at\n                    ) VALUES (\n                        gen_random_uuid(), $1, $2, $3, $4,\n                        'source', $5, $6, $7, $8,\n                        $9, $10, $11, $12,\n                        $13, $14, NOW(), NOW()\n                    )\n                ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', '1f86d6b8-d474-450a-a72e-ccc24c29e127', '96294047-e987-41b3-9237-686a7f32368c', '9e5368e1-5c00-4c64-a4b6-acf5f6ba5d11', 'payment-gateway-service', 'PaymentService.java', 15, None, 'main', 'key_generation', 'JAVA-RSA-001', '1.0', 'java-source', '1.0.0')]\n(Background on this error at: https://sqlalche.me/e/20/f405)	worker-45-ee79f5f0	\N	{"scan_id": "96294047-e987-41b3-9237-686a7f32368c", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	f	\N	bc60a98e-9daf-467a-9899-d6662c5e3c12	2026-09-22 04:10:23.466661+00	2026-09-22 04:10:23.466661+00
bdd27b4c-e0b6-411c-a240-bb2021033355	19e7e44b-6d63-4c16-9ef7-701b266550a7	816d9cad-340f-4d0f-8b8b-f92b74d88711	collect_source	2	(sqlalchemy.dialects.postgresql.asyncpg.IntegrityError) <class 'asyncpg.exceptions.ForeignKeyViolationError'>: insert or update on table "occurrences" violates foreign key constraint "occurrences_collector_run_id_fkey"\nDETAIL:  Key (collector_run_id)=(bdd27b4c-e0b6-411c-a240-bb2021033355) is not present in table "collector_runs".\n[SQL: \n                    INSERT INTO occurrences (\n                        id, tenant_id, asset_id, scan_id, collector_run_id,\n                        location_type, repository, file_path, line, "column",\n                        commit_ref, observation_type, detection_rule_id, detection_rule_version,\n                        collector_name, collector_version, created_at, updated_at\n                    ) VALUES (\n                        gen_random_uuid(), $1, $2, $3, $4,\n                        'source', $5, $6, $7, $8,\n                        $9, $10, $11, $12,\n                        $13, $14, NOW(), NOW()\n                    )\n                ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', '4763f787-c010-433d-b441-9ff78e47d955', '816d9cad-340f-4d0f-8b8b-f92b74d88711', 'bdd27b4c-e0b6-411c-a240-bb2021033355', 'payment-gateway-service', 'PaymentService.java', 15, None, 'main', 'key_generation', 'JAVA-RSA-001', '1.0', 'java-source', '1.0.0')]\n(Background on this error at: https://sqlalche.me/e/20/gkpj)	worker-69-f9df30b4	\N	{"scan_id": "816d9cad-340f-4d0f-8b8b-f92b74d88711", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	f	\N	ec12ce9c-8733-46cc-83d2-3fa6247a1119	2026-09-22 04:11:01.293019+00	2026-09-22 04:11:01.293019+00
a6c0f746-9c40-4f0f-bac5-759ebfa49d13	19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	calculate_risk	2	(sqlalchemy.dialects.postgresql.asyncpg.Error) <class 'asyncpg.exceptions.InvalidTextRepresentationError'>: invalid input value for enum analysisstatus: "excluded"\n[SQL: \n            SELECT DISTINCT a.id, a.algorithm, a.algorithm_normalized,\n                   a.asset_type, a.extra\n            FROM assets a\n            JOIN occurrences o ON o.asset_id = a.id\n            WHERE o.scan_id = $1\n              AND a.tenant_id = $2\n              AND a.analysis_status != 'excluded'\n        ]\n[parameters: ('f0e737fc-0460-4398-9493-42c4c3279e82', '19e7e44b-6d63-4c16-9ef7-701b266550a7')]\n(Background on this error at: https://sqlalche.me/e/20/dbapi)	worker-45-4a8fbe75	\N	{"scan_id": "f0e737fc-0460-4398-9493-42c4c3279e82", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	f	\N	55565c0c-eb08-452d-90d3-58ded97d7173	2026-09-22 04:12:23.020032+00	2026-09-22 04:12:23.020032+00
3d17e5c0-fbc6-4e2f-9836-35dcefc63893	19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	evaluate_policy	2	(sqlalchemy.dialects.postgresql.asyncpg.Error) <class 'asyncpg.exceptions.InvalidTextRepresentationError'>: invalid input value for enum policypackstatus: "active"\n[SQL: \n            SELECT id, name, version\n            FROM policy_packs\n            WHERE (tenant_id = $1 OR tenant_id = '00000000-0000-0000-0000-000000000000')\n              AND status = 'active'\n        ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7',)]\n(Background on this error at: https://sqlalche.me/e/20/dbapi)	worker-45-4a8fbe75	\N	{"scan_id": "f0e737fc-0460-4398-9493-42c4c3279e82", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	f	\N	18ebc80e-d121-4828-8f2e-fb02cebe4692	2026-09-22 04:12:23.140928+00	2026-09-22 04:12:23.140928+00
fc2f0a01-5322-48a7-b87c-5e0136a63273	19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	create_snapshot	2	Object of type UUID is not JSON serializable	worker-45-4a8fbe75	\N	{"scan_id": "f0e737fc-0460-4398-9493-42c4c3279e82", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	f	\N	5989cded-f787-44f8-929f-89eb649b691d	2026-09-22 04:12:23.361471+00	2026-09-22 04:12:23.361471+00
01cec386-e334-482c-82ec-8a98c2ef5336	19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	calculate_risk	2	(sqlalchemy.dialects.postgresql.asyncpg.ProgrammingError) <class 'asyncpg.exceptions.InvalidColumnReferenceError'>: there is no unique or exclusion constraint matching the ON CONFLICT specification\n[SQL: \n                INSERT INTO risk_assessments (\n                    id, tenant_id, asset_id, scan_id,\n                    risk_profile_id, risk_profile_version,\n                    x_value, x_source, x_override,\n                    y_value, y_min, y_max, y_source,\n                    mosca_results,\n                    qars_temporal, qars_sensitivity, qars_exposure, qars_score,\n                    created_at, updated_at\n                ) VALUES (\n                    gen_random_uuid(), $1, $2, $3,\n                    $4, $5,\n                    $6, $7, false,\n                    $8, $9, $10, $11,\n                    $12,\n                    $13, $14, $15, $16,\n                    NOW(), NOW()\n                )\n                ON CONFLICT (asset_id, scan_id) DO UPDATE SET\n                    qars_score = EXCLUDED.qars_score,\n                    qars_temporal = EXCLUDED.qars_temporal,\n                    qars_sensitivity = EXCLUDED.qars_sensitivity,\n                    qars_exposure = EXCLUDED.qars_exposure,\n                    mosca_results = EXCLUDED.mosca_results,\n                    x_value = EXCLUDED.x_value,\n                    y_value = EXCLUDED.y_value,\n                    risk_profile_version = EXCLUDED.risk_profile_version,\n                    updated_at = NOW()\n            ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', '514541ce-a2e7-41d7-9e66-152e3d63da8a', '690dbd77-e499-4a4d-8f4a-ed301b8624d2', '1e5d1f2b-83ca-5268-bfdf-65cf67b073ad', '1.0', 10.0, 'default_conservative', 3.0, 1.0, 5.0, 'migration_estimate_v1.0', '{"x_value": 10.0, "x_source": "default_conservative", "y_value": 3.0, "y_min": 1.0, "y_max": 5.0, "y_source": "migration_estimate_v1.0", "z_conservat ... (216 characters truncated) ... .0, "verdict": "act_now", "margin_years": 3.0}, {"labe	worker-45-a6f95264	\N	{"scan_id": "690dbd77-e499-4a4d-8f4a-ed301b8624d2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	f	\N	29253317-0402-40d7-bcff-eae627a3e61c	2026-09-22 04:14:38.398066+00	2026-09-22 04:14:38.398066+00
\.


--
-- Data for Name: evidence; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.evidence (tenant_id, occurrence_id, content_hash, content_type, size_bytes, storage_uri, inline_content, retention_until, retention_hold, collector_name, collector_version, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: exemptions; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.exemptions (tenant_id, policy_result_id, rule_id, asset_id, scope, reason, owner, approver, expires_at, is_active, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: job_attempts; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.job_attempts (job_id, attempt_number, worker_id, state, started_at, completed_at, error_code, error_message, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: job_events; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.job_events (job_id, event_type, old_state, new_state, worker_id, detail, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: jobs; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.jobs (tenant_id, scan_id, job_type, state, priority, idempotency_key, attempt, max_attempts, scheduled_at, started_at, completed_at, lease_until, worker_id, error_code, error_class, error_message, input_hash, payload, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	scan_create	succeeded	1	SCAN_CREATE-7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	1	5	\N	2026-09-22 16:42:34.913399+00	2026-09-22 16:42:34.913399+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "7bcc5ead-dd89-450f-a7a5-c58747fdc9a2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	e2cf9a66-5bde-4058-95ce-cea531b50769	2026-09-22 16:42:34.745658+00	2026-09-22 16:42:34.745658+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	c51fe79c-a401-4d54-8001-456d65442e98	scan_create	succeeded	1	SCAN_CREATE-c51fe79c-a401-4d54-8001-456d65442e98	1	5	\N	2026-09-22 03:50:46.129888+00	2026-09-22 03:50:46.129888+00	\N	worker-66-31e0fdfb	\N	\N	\N	\N	{"scan_id": "c51fe79c-a401-4d54-8001-456d65442e98", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	49301fbd-8520-432c-be9d-2f77896c4f91	2026-09-22 03:50:45.703235+00	2026-09-22 03:50:45.703235+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	scan_create	succeeded	1	SCAN_CREATE-40fe6196-d1ed-4b6c-a0df-b9ef84e721af	1	5	\N	2026-09-22 16:44:03.671945+00	2026-09-22 16:44:03.671945+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "40fe6196-d1ed-4b6c-a0df-b9ef84e721af", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	926df3bb-7f2c-41d6-a6fc-d4800c89e259	2026-09-22 16:44:03.004803+00	2026-09-22 16:44:03.004803+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	c51fe79c-a401-4d54-8001-456d65442e98	collect_source	failed_final	5	COLLECT_SOURCE-c51fe79c-a401-4d54-8001-456d65442e98	1	5	\N	2026-09-22 03:56:14.910855+00	2026-09-22 03:56:14.910855+00	2026-09-22 04:01:14.910855+00	worker-66-47c11e26	\N	\N	'EvidenceEnvelope' object has no attribute 'rule'	\N	{"scan_id": "c51fe79c-a401-4d54-8001-456d65442e98", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	e38f7754-f49a-4972-a681-dfb8abbcd806	2026-09-22 03:50:46.164228+00	2026-09-22 03:50:46.164228+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	a1b341a0-deb5-450e-b363-066fed45ef60	collect_source	failed_final	5	COLLECT_SOURCE-a1b341a0-deb5-450e-b363-066fed45ef60	1	5	\N	2026-09-22 03:56:14.911529+00	2026-09-22 03:56:14.911529+00	2026-09-22 04:01:14.911529+00	worker-66-47c11e26	\N	\N	'EvidenceEnvelope' object has no attribute 'rule'	\N	{"scan_id": "a1b341a0-deb5-450e-b363-066fed45ef60", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	a2f55c86-a233-4b4d-be80-410c9b263081	2026-09-22 03:52:26.079616+00	2026-09-22 03:52:26.079616+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	9f008610-d735-47d9-80a3-3a52020c90f0	collect_source	failed_final	5	COLLECT_SOURCE-9f008610-d735-47d9-80a3-3a52020c90f0	1	5	\N	2026-09-22 03:56:14.939442+00	2026-09-22 03:56:14.939442+00	2026-09-22 04:01:14.939442+00	worker-66-47c11e26	\N	\N	'EvidenceEnvelope' object has no attribute 'rule'	\N	{"scan_id": "9f008610-d735-47d9-80a3-3a52020c90f0", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	af3f5778-98a0-46e8-948c-3332e74b9ecf	2026-09-22 03:54:55.90332+00	2026-09-22 03:54:55.90332+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	024b13c4-3c2b-41bb-aa55-502939749cb0	scan_create	succeeded	1	SCAN_CREATE-024b13c4-3c2b-41bb-aa55-502939749cb0	1	5	\N	2026-09-22 04:08:24.894404+00	2026-09-22 04:08:24.894404+00	\N	worker-66-f3503e02	\N	\N	\N	\N	{"scan_id": "024b13c4-3c2b-41bb-aa55-502939749cb0", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	4152bf65-806e-4ed5-86bb-d8ff0dc79568	2026-09-22 04:08:24.62325+00	2026-09-22 04:08:24.62325+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	evaluate_policy	succeeded	11	EVALUATE_POLICY-690dbd77-e499-4a4d-8f4a-ed301b8624d2	1	5	\N	2026-09-22 04:14:38.499871+00	2026-09-22 04:14:38.499871+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "690dbd77-e499-4a4d-8f4a-ed301b8624d2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	a5c2e94a-5dc1-4bfa-aa7c-65b582592e5c	2026-09-22 04:14:38.375723+00	2026-09-22 04:14:38.375723+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	generate_advisory	succeeded	12	GENERATE_ADVISORY-690dbd77-e499-4a4d-8f4a-ed301b8624d2	1	5	\N	2026-09-22 04:14:38.672822+00	2026-09-22 04:14:38.672822+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "690dbd77-e499-4a4d-8f4a-ed301b8624d2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	ac6c5079-f00c-4bda-abb4-a77f39a35469	2026-09-22 04:14:38.375723+00	2026-09-22 04:14:38.375723+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	create_snapshot	succeeded	15	CREATE_SNAPSHOT-690dbd77-e499-4a4d-8f4a-ed301b8624d2	1	5	\N	2026-09-22 04:14:38.708433+00	2026-09-22 04:14:38.708433+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "690dbd77-e499-4a4d-8f4a-ed301b8624d2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	1374a81c-ed92-4ee1-8e45-784f2785080c	2026-09-22 04:14:38.375723+00	2026-09-22 04:14:38.375723+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	a1b341a0-deb5-450e-b363-066fed45ef60	scan_create	succeeded	1	SCAN_CREATE-a1b341a0-deb5-450e-b363-066fed45ef60	1	5	\N	2026-09-22 03:52:26.078152+00	2026-09-22 03:52:26.078152+00	\N	worker-66-95dc03ec	\N	\N	\N	\N	{"scan_id": "a1b341a0-deb5-450e-b363-066fed45ef60", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	b5f960e8-83de-4f5a-ab61-97caac7ab3be	2026-09-22 03:52:25.075889+00	2026-09-22 03:52:25.075889+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	9f008610-d735-47d9-80a3-3a52020c90f0	scan_create	succeeded	1	SCAN_CREATE-9f008610-d735-47d9-80a3-3a52020c90f0	1	5	\N	2026-09-22 03:54:55.901702+00	2026-09-22 03:54:55.901702+00	\N	worker-66-47c11e26	\N	\N	\N	\N	{"scan_id": "9f008610-d735-47d9-80a3-3a52020c90f0", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	b588e64e-026c-4c56-8add-6b1f5b369459	2026-09-22 03:54:55.628486+00	2026-09-22 03:54:55.628486+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	024b13c4-3c2b-41bb-aa55-502939749cb0	collect_source	failed_final	5	COLLECT_SOURCE-024b13c4-3c2b-41bb-aa55-502939749cb0	1	5	\N	2026-09-22 04:08:24.997511+00	2026-09-22 04:08:24.997511+00	2026-09-22 04:13:24.997511+00	worker-66-f3503e02	\N	\N	(sqlalchemy.dialects.postgresql.asyncpg.ProgrammingError) <class 'asyncpg.exceptions.InvalidColumnReferenceError'>: there is no unique or exclusion constraint matching the ON CONFLICT specification\n[SQL: \n                    INSERT INTO assets (id, tenant_id, stable_id, match_type, asset_type, algorithm,\n                                        algorithm_normalized, key_size, curve, provider, operation,\n                                        confidence, analysis_status, usage_evidence,\n                                        has_conflict, extra)\n                    VALUES (gen_random_uuid(), $1, $2, $3, $4,\n                            $5, $6, $7, $8, $9, $10,\n                            $11, $12, $13,\n                            false, $14)\n                    ON CONFLICT (stable_id) DO UPDATE SET\n                        algorithm = EXCLUDED.algorithm,\n                        algorithm_normalized = EXCLUDED.algorithm_normalized,\n                        confidence = EXCLUDED.confidence,\n                        extra = EXCLUDED.extra\n                    RETURNING id\n                ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', 'sha256:6e1312395b4030210127fc856c4744d3c43172bcc96f393f742356a3f8ef7168', 'repo_path_semantic', 'algorithm', 'RSA', 'RSA', None, None, None, None, 'confirmed', 'observed', 'static', '{"key_size": null, "curve": null, "provider": null, "operation": null}')]\n(Background on this error at: https://sqlalche.me/e/20/f405)	\N	{"scan_id": "024b13c4-3c2b-41bb-aa55-502939749cb0", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	e0e05b21-1f36-423c-8fdb-081679af4333	2026-09-22 04:08:24.9548+00	2026-09-22 04:08:24.9548+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	collect_source	succeeded	5	COLLECT_SOURCE-7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	1	5	\N	2026-09-22 16:42:35.149848+00	2026-09-22 16:42:35.149848+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "7bcc5ead-dd89-450f-a7a5-c58747fdc9a2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	52a9d485-59e3-44a6-90cc-f731294ede20	2026-09-22 16:42:35.055117+00	2026-09-22 16:42:35.055117+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	evaluate_policy	succeeded	11	EVALUATE_POLICY-7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	1	5	\N	2026-09-22 16:42:36.648134+00	2026-09-22 16:42:36.648134+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "7bcc5ead-dd89-450f-a7a5-c58747fdc9a2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	6c3b100b-3e6e-4eb4-909a-35a2a2001e97	2026-09-22 16:42:36.36347+00	2026-09-22 16:42:36.36347+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	55b8a79d-a57c-4410-82fd-dcf19e933127	scan_create	succeeded	1	SCAN_CREATE-55b8a79d-a57c-4410-82fd-dcf19e933127	1	5	\N	2026-09-22 04:09:39.991529+00	2026-09-22 04:09:39.991529+00	\N	worker-45-aac7fee1	\N	\N	\N	\N	{"scan_id": "55b8a79d-a57c-4410-82fd-dcf19e933127", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	e69e8608-87b4-421e-8f93-d6cc882298c2	2026-09-22 04:09:39.04518+00	2026-09-22 04:09:39.04518+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	55b8a79d-a57c-4410-82fd-dcf19e933127	collect_source	failed_final	5	COLLECT_SOURCE-55b8a79d-a57c-4410-82fd-dcf19e933127	1	5	\N	2026-09-22 04:09:40.042559+00	2026-09-22 04:09:40.042559+00	2026-09-22 04:14:40.042559+00	worker-45-aac7fee1	\N	\N	(sqlalchemy.dialects.postgresql.asyncpg.ProgrammingError) <class 'asyncpg.exceptions.PostgresSyntaxError'>: syntax error at or near "column"\n[SQL: \n                    INSERT INTO occurrences (\n                        id, tenant_id, asset_id, scan_id, collector_run_id,\n                        location_type, repository, file_path, line, column,\n                        commit_ref, observation_type, detection_rule_id, detection_rule_version,\n                        collector_name, collector_version, created_at, updated_at\n                    ) VALUES (\n                        gen_random_uuid(), $1, $2, $3, $4,\n                        'source', $5, $6, $7, $8,\n                        $9, $10, $11, $12,\n                        $13, $14, NOW(), NOW()\n                    )\n                ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', 'ae5ea825-7b20-4889-9b7e-87ca4a19c634', '55b8a79d-a57c-4410-82fd-dcf19e933127', 'accf317d-42bf-4d7b-a695-963991e7d67d', 'payment-gateway-service', 'PaymentService.java', 15, None, 'main', 'key_generation', 'JAVA-RSA-001', '1.0', 'java-source', '1.0.0')]\n(Background on this error at: https://sqlalche.me/e/20/f405)	\N	{"scan_id": "55b8a79d-a57c-4410-82fd-dcf19e933127", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	accf317d-42bf-4d7b-a695-963991e7d67d	2026-09-22 04:09:40.014912+00	2026-09-22 04:09:40.014912+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	96294047-e987-41b3-9237-686a7f32368c	scan_create	succeeded	1	SCAN_CREATE-96294047-e987-41b3-9237-686a7f32368c	1	5	\N	2026-09-22 04:10:23.418754+00	2026-09-22 04:10:23.418754+00	\N	worker-45-ee79f5f0	\N	\N	\N	\N	{"scan_id": "96294047-e987-41b3-9237-686a7f32368c", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	02cdad20-6793-4d60-b58a-453398b2affb	2026-09-22 04:10:22.675208+00	2026-09-22 04:10:22.675208+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	calculate_risk	failed_final	10	CALCULATE_RISK-f0e737fc-0460-4398-9493-42c4c3279e82	1	5	\N	2026-09-22 04:12:23.020032+00	2026-09-22 04:12:23.020032+00	2026-09-22 04:17:23.020032+00	worker-45-4a8fbe75	\N	\N	(sqlalchemy.dialects.postgresql.asyncpg.Error) <class 'asyncpg.exceptions.InvalidTextRepresentationError'>: invalid input value for enum analysisstatus: "excluded"\n[SQL: \n            SELECT DISTINCT a.id, a.algorithm, a.algorithm_normalized,\n                   a.asset_type, a.extra\n            FROM assets a\n            JOIN occurrences o ON o.asset_id = a.id\n            WHERE o.scan_id = $1\n              AND a.tenant_id = $2\n              AND a.analysis_status != 'excluded'\n        ]\n[parameters: ('f0e737fc-0460-4398-9493-42c4c3279e82', '19e7e44b-6d63-4c16-9ef7-701b266550a7')]\n(Background on this error at: https://sqlalche.me/e/20/dbapi)	\N	{"scan_id": "f0e737fc-0460-4398-9493-42c4c3279e82", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	a6c0f746-9c40-4f0f-bac5-759ebfa49d13	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	generate_advisory	succeeded	12	GENERATE_ADVISORY-f0e737fc-0460-4398-9493-42c4c3279e82	1	5	\N	2026-09-22 04:12:23.276234+00	2026-09-22 04:12:23.276234+00	\N	worker-45-4a8fbe75	\N	\N	\N	\N	{"scan_id": "f0e737fc-0460-4398-9493-42c4c3279e82", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	1279eb6e-2978-4d30-bed2-1837f1d54fc6	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	96294047-e987-41b3-9237-686a7f32368c	collect_source	failed_final	5	COLLECT_SOURCE-96294047-e987-41b3-9237-686a7f32368c	1	5	\N	2026-09-22 04:10:23.466661+00	2026-09-22 04:10:23.466661+00	2026-09-22 04:15:23.466661+00	worker-45-ee79f5f0	\N	\N	(sqlalchemy.dialects.postgresql.asyncpg.ProgrammingError) <class 'asyncpg.exceptions.PostgresSyntaxError'>: syntax error at or near "column"\n[SQL: \n                    INSERT INTO occurrences (\n                        id, tenant_id, asset_id, scan_id, collector_run_id,\n                        location_type, repository, file_path, line, column,\n                        commit_ref, observation_type, detection_rule_id, detection_rule_version,\n                        collector_name, collector_version, created_at, updated_at\n                    ) VALUES (\n                        gen_random_uuid(), $1, $2, $3, $4,\n                        'source', $5, $6, $7, $8,\n                        $9, $10, $11, $12,\n                        $13, $14, NOW(), NOW()\n                    )\n                ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', '1f86d6b8-d474-450a-a72e-ccc24c29e127', '96294047-e987-41b3-9237-686a7f32368c', '9e5368e1-5c00-4c64-a4b6-acf5f6ba5d11', 'payment-gateway-service', 'PaymentService.java', 15, None, 'main', 'key_generation', 'JAVA-RSA-001', '1.0', 'java-source', '1.0.0')]\n(Background on this error at: https://sqlalche.me/e/20/f405)	\N	{"scan_id": "96294047-e987-41b3-9237-686a7f32368c", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	9e5368e1-5c00-4c64-a4b6-acf5f6ba5d11	2026-09-22 04:10:23.443857+00	2026-09-22 04:10:23.443857+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	816d9cad-340f-4d0f-8b8b-f92b74d88711	scan_create	succeeded	1	SCAN_CREATE-816d9cad-340f-4d0f-8b8b-f92b74d88711	1	5	\N	2026-09-22 04:11:01.25231+00	2026-09-22 04:11:01.25231+00	\N	worker-69-f9df30b4	\N	\N	\N	\N	{"scan_id": "816d9cad-340f-4d0f-8b8b-f92b74d88711", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	8725de26-80aa-4f21-8b6f-0aaa0a9f5a31	2026-09-22 04:11:00.32122+00	2026-09-22 04:11:00.32122+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	816d9cad-340f-4d0f-8b8b-f92b74d88711	collect_source	failed_final	5	COLLECT_SOURCE-816d9cad-340f-4d0f-8b8b-f92b74d88711	1	5	\N	2026-09-22 04:11:01.293019+00	2026-09-22 04:11:01.293019+00	2026-09-22 04:16:01.293019+00	worker-69-f9df30b4	\N	\N	(sqlalchemy.dialects.postgresql.asyncpg.IntegrityError) <class 'asyncpg.exceptions.ForeignKeyViolationError'>: insert or update on table "occurrences" violates foreign key constraint "occurrences_collector_run_id_fkey"\nDETAIL:  Key (collector_run_id)=(bdd27b4c-e0b6-411c-a240-bb2021033355) is not present in table "collector_runs".\n[SQL: \n                    INSERT INTO occurrences (\n                        id, tenant_id, asset_id, scan_id, collector_run_id,\n                        location_type, repository, file_path, line, "column",\n                        commit_ref, observation_type, detection_rule_id, detection_rule_version,\n                        collector_name, collector_version, created_at, updated_at\n                    ) VALUES (\n                        gen_random_uuid(), $1, $2, $3, $4,\n                        'source', $5, $6, $7, $8,\n                        $9, $10, $11, $12,\n                        $13, $14, NOW(), NOW()\n                    )\n                ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', '4763f787-c010-433d-b441-9ff78e47d955', '816d9cad-340f-4d0f-8b8b-f92b74d88711', 'bdd27b4c-e0b6-411c-a240-bb2021033355', 'payment-gateway-service', 'PaymentService.java', 15, None, 'main', 'key_generation', 'JAVA-RSA-001', '1.0', 'java-source', '1.0.0')]\n(Background on this error at: https://sqlalche.me/e/20/gkpj)	\N	{"scan_id": "816d9cad-340f-4d0f-8b8b-f92b74d88711", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	bdd27b4c-e0b6-411c-a240-bb2021033355	2026-09-22 04:11:01.272962+00	2026-09-22 04:11:01.272962+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	calculate_risk	succeeded	10	CALCULATE_RISK-7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	1	5	\N	2026-09-22 16:42:36.406453+00	2026-09-22 16:42:36.406453+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "7bcc5ead-dd89-450f-a7a5-c58747fdc9a2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	b010b8dc-f92e-4867-9813-cf8154ab8246	2026-09-22 16:42:36.36347+00	2026-09-22 16:42:36.36347+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	scan_create	succeeded	1	SCAN_CREATE-f0e737fc-0460-4398-9493-42c4c3279e82	1	5	\N	2026-09-22 04:12:22.535301+00	2026-09-22 04:12:22.535301+00	\N	worker-45-4a8fbe75	\N	\N	\N	\N	{"scan_id": "f0e737fc-0460-4398-9493-42c4c3279e82", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	9c025fd0-bba4-400f-b912-5bdb8fc5764a	2026-09-22 04:12:21.794485+00	2026-09-22 04:12:21.794485+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	collect_source	succeeded	5	COLLECT_SOURCE-f0e737fc-0460-4398-9493-42c4c3279e82	1	5	\N	2026-09-22 04:12:22.582375+00	2026-09-22 04:12:22.582375+00	\N	worker-45-4a8fbe75	\N	\N	\N	\N	{"scan_id": "f0e737fc-0460-4398-9493-42c4c3279e82", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	4ab5ffe1-41d9-49e6-8a6b-118b8dd02196	2026-09-22 04:12:22.56109+00	2026-09-22 04:12:22.56109+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	evaluate_policy	failed_final	11	EVALUATE_POLICY-f0e737fc-0460-4398-9493-42c4c3279e82	1	5	\N	2026-09-22 04:12:23.140928+00	2026-09-22 04:12:23.140928+00	2026-09-22 04:17:23.140928+00	worker-45-4a8fbe75	\N	\N	(sqlalchemy.dialects.postgresql.asyncpg.Error) <class 'asyncpg.exceptions.InvalidTextRepresentationError'>: invalid input value for enum policypackstatus: "active"\n[SQL: \n            SELECT id, name, version\n            FROM policy_packs\n            WHERE (tenant_id = $1 OR tenant_id = '00000000-0000-0000-0000-000000000000')\n              AND status = 'active'\n        ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7',)]\n(Background on this error at: https://sqlalche.me/e/20/dbapi)	\N	{"scan_id": "f0e737fc-0460-4398-9493-42c4c3279e82", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	3d17e5c0-fbc6-4e2f-9836-35dcefc63893	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	f0e737fc-0460-4398-9493-42c4c3279e82	create_snapshot	failed_final	15	CREATE_SNAPSHOT-f0e737fc-0460-4398-9493-42c4c3279e82	1	5	\N	2026-09-22 04:12:23.361471+00	2026-09-22 04:12:23.361471+00	2026-09-22 04:17:23.361471+00	worker-45-4a8fbe75	\N	\N	Object of type UUID is not JSON serializable	\N	{"scan_id": "f0e737fc-0460-4398-9493-42c4c3279e82", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	fc2f0a01-5322-48a7-b87c-5e0136a63273	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	generate_advisory	succeeded	12	GENERATE_ADVISORY-7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	1	5	\N	2026-09-22 16:42:37.023612+00	2026-09-22 16:42:37.023612+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "7bcc5ead-dd89-450f-a7a5-c58747fdc9a2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	01d0ab9e-ca5f-4887-a120-6f4f86c2c344	2026-09-22 16:42:36.36347+00	2026-09-22 16:42:36.36347+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	scan_create	succeeded	1	SCAN_CREATE-690dbd77-e499-4a4d-8f4a-ed301b8624d2	1	5	\N	2026-09-22 04:14:37.760597+00	2026-09-22 04:14:37.760597+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "690dbd77-e499-4a4d-8f4a-ed301b8624d2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	6be4cd86-1ae9-480b-9ba1-87e0d39f43d3	2026-09-22 04:14:37.269558+00	2026-09-22 04:14:37.269558+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	collect_source	succeeded	5	COLLECT_SOURCE-40fe6196-d1ed-4b6c-a0df-b9ef84e721af	1	5	\N	2026-09-22 16:44:03.693995+00	2026-09-22 16:44:03.693995+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "40fe6196-d1ed-4b6c-a0df-b9ef84e721af", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	e93835d4-a782-432b-b59e-1335988c5413	2026-09-22 16:44:03.674929+00	2026-09-22 16:44:03.674929+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	collect_source	succeeded	5	COLLECT_SOURCE-690dbd77-e499-4a4d-8f4a-ed301b8624d2	1	5	\N	2026-09-22 04:14:37.813954+00	2026-09-22 04:14:37.813954+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "690dbd77-e499-4a4d-8f4a-ed301b8624d2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	a0e01229-164c-4d88-bff0-bece50b43de0	2026-09-22 04:14:37.784076+00	2026-09-22 04:14:37.784076+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	collect_source	succeeded	5	COLLECT_SOURCE-e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	1	5	\N	2026-09-22 04:17:03.710654+00	2026-09-22 04:17:03.710654+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	a42a2425-bb2f-4653-b5a9-50a291aae70e	2026-09-22 04:17:03.703902+00	2026-09-22 04:17:03.703902+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	calculate_risk	failed_final	10	CALCULATE_RISK-690dbd77-e499-4a4d-8f4a-ed301b8624d2	1	5	\N	2026-09-22 04:14:38.398066+00	2026-09-22 04:14:38.398066+00	2026-09-22 04:19:38.398066+00	worker-45-a6f95264	\N	\N	(sqlalchemy.dialects.postgresql.asyncpg.ProgrammingError) <class 'asyncpg.exceptions.InvalidColumnReferenceError'>: there is no unique or exclusion constraint matching the ON CONFLICT specification\n[SQL: \n                INSERT INTO risk_assessments (\n                    id, tenant_id, asset_id, scan_id,\n                    risk_profile_id, risk_profile_version,\n                    x_value, x_source, x_override,\n                    y_value, y_min, y_max, y_source,\n                    mosca_results,\n                    qars_temporal, qars_sensitivity, qars_exposure, qars_score,\n                    created_at, updated_at\n                ) VALUES (\n                    gen_random_uuid(), $1, $2, $3,\n                    $4, $5,\n                    $6, $7, false,\n                    $8, $9, $10, $11,\n                    $12,\n                    $13, $14, $15, $16,\n                    NOW(), NOW()\n                )\n                ON CONFLICT (asset_id, scan_id) DO UPDATE SET\n                    qars_score = EXCLUDED.qars_score,\n                    qars_temporal = EXCLUDED.qars_temporal,\n                    qars_sensitivity = EXCLUDED.qars_sensitivity,\n                    qars_exposure = EXCLUDED.qars_exposure,\n                    mosca_results = EXCLUDED.mosca_results,\n                    x_value = EXCLUDED.x_value,\n                    y_value = EXCLUDED.y_value,\n                    risk_profile_version = EXCLUDED.risk_profile_version,\n                    updated_at = NOW()\n            ]\n[parameters: ('19e7e44b-6d63-4c16-9ef7-701b266550a7', '514541ce-a2e7-41d7-9e66-152e3d63da8a', '690dbd77-e499-4a4d-8f4a-ed301b8624d2', '1e5d1f2b-83ca-5268-bfdf-65cf67b073ad', '1.0', 10.0, 'default_conservative', 3.0, 1.0, 5.0, 'migration_estimate_v1.0', '{"x_value": 10.0, "x_source": "default_conservative", "y_value": 3.0, "y_min": 1.0, "y_max": 5.0, "y_source": "migration_estimate_v1.0", "z_conservat ... (216 characters truncated) ... .0, "verdict": "act_now", "margin_years": 3.0}, {"labe	\N	{"scan_id": "690dbd77-e499-4a4d-8f4a-ed301b8624d2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	01cec386-e334-482c-82ec-8a98c2ef5336	2026-09-22 04:14:38.375723+00	2026-09-22 04:14:38.375723+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	create_snapshot	succeeded	15	CREATE_SNAPSHOT-7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	1	5	\N	2026-09-22 16:42:37.108062+00	2026-09-22 16:42:37.108062+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "7bcc5ead-dd89-450f-a7a5-c58747fdc9a2", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	979a0fbf-f122-4415-b09f-1a40a44a054c	2026-09-22 16:42:36.36347+00	2026-09-22 16:42:36.36347+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	scan_create	succeeded	1	SCAN_CREATE-e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	1	5	\N	2026-09-22 04:17:03.700309+00	2026-09-22 04:17:03.700309+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7", "commit_ref": "main", "target_path": "/app/sample_estate/payment-gateway-service", "repository_id": "656af2f9-d7a2-4831-9237-2707b912a603", "repository_name": "payment-gateway-service"}	2c441790-75b0-497c-ad37-0338f11d4a42	2026-09-22 04:17:03.493668+00	2026-09-22 04:17:03.493668+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	calculate_risk	succeeded	10	CALCULATE_RISK-e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	1	5	\N	2026-09-22 04:17:03.802674+00	2026-09-22 04:17:03.802674+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	d70b1d83-0edd-412f-983b-bedcb612afd6	2026-09-22 04:17:03.780453+00	2026-09-22 04:17:03.780453+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	evaluate_policy	succeeded	11	EVALUATE_POLICY-e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	1	5	\N	2026-09-22 04:17:03.820736+00	2026-09-22 04:17:03.820736+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	f43d4a3e-1387-421c-aa23-2e9e0e6d110f	2026-09-22 04:17:03.780453+00	2026-09-22 04:17:03.780453+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	generate_advisory	succeeded	12	GENERATE_ADVISORY-e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	1	5	\N	2026-09-22 04:17:03.853856+00	2026-09-22 04:17:03.853856+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	3f3d4f53-cc55-428b-aa98-276cb208b747	2026-09-22 04:17:03.780453+00	2026-09-22 04:17:03.780453+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	create_snapshot	succeeded	15	CREATE_SNAPSHOT-e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	1	5	\N	2026-09-22 04:17:03.861426+00	2026-09-22 04:17:03.861426+00	\N	worker-45-a6f95264	\N	\N	\N	\N	{"scan_id": "e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	ba108ca5-50af-4e5e-8143-6483e3c4659a	2026-09-22 04:17:03.780453+00	2026-09-22 04:17:03.780453+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	calculate_risk	succeeded	10	CALCULATE_RISK-40fe6196-d1ed-4b6c-a0df-b9ef84e721af	1	5	\N	2026-09-22 16:44:03.792848+00	2026-09-22 16:44:03.792848+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "40fe6196-d1ed-4b6c-a0df-b9ef84e721af", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	965e8001-562d-4db7-ae8a-0c42ce0e624c	2026-09-22 16:44:03.760989+00	2026-09-22 16:44:03.760989+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	generate_advisory	succeeded	12	GENERATE_ADVISORY-40fe6196-d1ed-4b6c-a0df-b9ef84e721af	1	5	\N	2026-09-22 16:44:03.795378+00	2026-09-22 16:44:03.795378+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "40fe6196-d1ed-4b6c-a0df-b9ef84e721af", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	5685eff0-89f7-4352-91c1-c3fe1ebb67a9	2026-09-22 16:44:03.760989+00	2026-09-22 16:44:03.760989+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	create_snapshot	succeeded	15	CREATE_SNAPSHOT-40fe6196-d1ed-4b6c-a0df-b9ef84e721af	1	5	\N	2026-09-22 16:44:03.795611+00	2026-09-22 16:44:03.795611+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "40fe6196-d1ed-4b6c-a0df-b9ef84e721af", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	f2b1299b-c57c-40d3-832d-d4cb6acad2ee	2026-09-22 16:44:03.760989+00	2026-09-22 16:44:03.760989+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	evaluate_policy	succeeded	11	EVALUATE_POLICY-40fe6196-d1ed-4b6c-a0df-b9ef84e721af	1	5	\N	2026-09-22 16:44:03.795086+00	2026-09-22 16:44:03.795086+00	\N	worker-67-3cd84b2b	\N	\N	\N	\N	{"scan_id": "40fe6196-d1ed-4b6c-a0df-b9ef84e721af", "tenant_id": "19e7e44b-6d63-4c16-9ef7-701b266550a7"}	33bb61d3-4cde-480e-96c2-8d2756e79ce3	2026-09-22 16:44:03.760989+00	2026-09-22 16:44:03.760989+00
\.


--
-- Data for Name: occurrences; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.occurrences (tenant_id, asset_id, scan_id, collector_run_id, location_type, repository, file_path, line, "column", commit_ref, image_digest, layer_digest, observation_type, dependency_evidence_level, detection_rule_id, detection_rule_version, collector_name, collector_version, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	5150438b-3602-4908-8dc5-d5c154592a00	f0e737fc-0460-4398-9493-42c4c3279e82	4ab5ffe1-41d9-49e6-8a6b-118b8dd02196	source	payment-gateway-service	PaymentService.java	15	\N	main	\N	\N	key_generation	\N	JAVA-RSA-001	1.0	java-source	1.0.0	d472d637-dd3d-4402-950b-f1db2e70e727	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	514541ce-a2e7-41d7-9e66-152e3d63da8a	f0e737fc-0460-4398-9493-42c4c3279e82	4ab5ffe1-41d9-49e6-8a6b-118b8dd02196	source	payment-gateway-service	PaymentService.java	19	\N	main	\N	\N	signing	\N	SOURCE-AST-001	1.0	java-source	1.0.0	07d3d14e-c2d7-4461-ac5c-96cde4337a95	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	b0d8844a-aec9-47a8-b526-a242718ab205	f0e737fc-0460-4398-9493-42c4c3279e82	4ab5ffe1-41d9-49e6-8a6b-118b8dd02196	source	payment-gateway-service	PaymentService.java	22	\N	main	\N	\N	encryption	\N	JAVA-DES-001	1.0	java-source	1.0.0	0d00acd4-98ca-4fc0-9904-ac36d0218385	2026-09-22 04:12:22.99733+00	2026-09-22 04:12:22.99733+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	5150438b-3602-4908-8dc5-d5c154592a00	690dbd77-e499-4a4d-8f4a-ed301b8624d2	a0e01229-164c-4d88-bff0-bece50b43de0	source	payment-gateway-service	PaymentService.java	15	\N	main	\N	\N	key_generation	\N	JAVA-RSA-001	1.0	java-source	1.0.0	cad997c2-fd01-4ee4-ac66-760daa4f4a97	2026-09-22 04:14:38.375723+00	2026-09-22 04:14:38.375723+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	514541ce-a2e7-41d7-9e66-152e3d63da8a	690dbd77-e499-4a4d-8f4a-ed301b8624d2	a0e01229-164c-4d88-bff0-bece50b43de0	source	payment-gateway-service	PaymentService.java	19	\N	main	\N	\N	signing	\N	SOURCE-AST-001	1.0	java-source	1.0.0	c00deab8-4253-4c67-acb3-de097d2b9da4	2026-09-22 04:14:38.375723+00	2026-09-22 04:14:38.375723+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	b0d8844a-aec9-47a8-b526-a242718ab205	690dbd77-e499-4a4d-8f4a-ed301b8624d2	a0e01229-164c-4d88-bff0-bece50b43de0	source	payment-gateway-service	PaymentService.java	22	\N	main	\N	\N	encryption	\N	JAVA-DES-001	1.0	java-source	1.0.0	d556abc0-1976-4f77-9d6c-866ead9ca0c7	2026-09-22 04:14:38.375723+00	2026-09-22 04:14:38.375723+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	5150438b-3602-4908-8dc5-d5c154592a00	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	a42a2425-bb2f-4653-b5a9-50a291aae70e	source	payment-gateway-service	PaymentService.java	15	\N	main	\N	\N	key_generation	\N	JAVA-RSA-001	1.0	java-source	1.0.0	9278d4bc-7ade-446c-9905-239cfa7363bd	2026-09-22 04:17:03.780453+00	2026-09-22 04:17:03.780453+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	514541ce-a2e7-41d7-9e66-152e3d63da8a	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	a42a2425-bb2f-4653-b5a9-50a291aae70e	source	payment-gateway-service	PaymentService.java	19	\N	main	\N	\N	signing	\N	SOURCE-AST-001	1.0	java-source	1.0.0	94d32d4e-95a8-4819-b285-279a5b7079d9	2026-09-22 04:17:03.780453+00	2026-09-22 04:17:03.780453+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	b0d8844a-aec9-47a8-b526-a242718ab205	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	a42a2425-bb2f-4653-b5a9-50a291aae70e	source	payment-gateway-service	PaymentService.java	22	\N	main	\N	\N	encryption	\N	JAVA-DES-001	1.0	java-source	1.0.0	41cb1c51-9d66-40f5-ad40-93e4c32703ed	2026-09-22 04:17:03.780453+00	2026-09-22 04:17:03.780453+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	5150438b-3602-4908-8dc5-d5c154592a00	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	52a9d485-59e3-44a6-90cc-f731294ede20	source	payment-gateway-service	PaymentService.java	15	\N	main	\N	\N	key_generation	\N	JAVA-RSA-001	1.0	java-source	1.0.0	9a8316ca-b6b4-4f01-b684-f57db0ae8516	2026-09-22 16:42:36.36347+00	2026-09-22 16:42:36.36347+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	514541ce-a2e7-41d7-9e66-152e3d63da8a	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	52a9d485-59e3-44a6-90cc-f731294ede20	source	payment-gateway-service	PaymentService.java	19	\N	main	\N	\N	signing	\N	SOURCE-AST-001	1.0	java-source	1.0.0	9dbb62d2-055f-4efc-ba84-2bdb8c4470fd	2026-09-22 16:42:36.36347+00	2026-09-22 16:42:36.36347+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	b0d8844a-aec9-47a8-b526-a242718ab205	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	52a9d485-59e3-44a6-90cc-f731294ede20	source	payment-gateway-service	PaymentService.java	22	\N	main	\N	\N	encryption	\N	JAVA-DES-001	1.0	java-source	1.0.0	6873b659-62da-41ee-9125-866a5e27446c	2026-09-22 16:42:36.36347+00	2026-09-22 16:42:36.36347+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	5150438b-3602-4908-8dc5-d5c154592a00	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	e93835d4-a782-432b-b59e-1335988c5413	source	payment-gateway-service	PaymentService.java	15	\N	main	\N	\N	key_generation	\N	JAVA-RSA-001	1.0	java-source	1.0.0	6caf5d62-acea-481b-a4e4-232e65e185d0	2026-09-22 16:44:03.760989+00	2026-09-22 16:44:03.760989+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	514541ce-a2e7-41d7-9e66-152e3d63da8a	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	e93835d4-a782-432b-b59e-1335988c5413	source	payment-gateway-service	PaymentService.java	19	\N	main	\N	\N	signing	\N	SOURCE-AST-001	1.0	java-source	1.0.0	aa81b83d-8002-49cc-96ff-0674d3b87955	2026-09-22 16:44:03.760989+00	2026-09-22 16:44:03.760989+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	b0d8844a-aec9-47a8-b526-a242718ab205	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	e93835d4-a782-432b-b59e-1335988c5413	source	payment-gateway-service	PaymentService.java	22	\N	main	\N	\N	encryption	\N	JAVA-DES-001	1.0	java-source	1.0.0	3c3fa9d5-cdfd-4d87-aa59-a286ef764e71	2026-09-22 16:44:03.760989+00	2026-09-22 16:44:03.760989+00
\.


--
-- Data for Name: policy_packs; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.policy_packs (tenant_id, name, version, status, source_document, source_version, published_at, effective_from, effective_until, jurisdiction, checksum, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	ECDAT Standard Baseline	1.0	ACTIVE	\N	\N	\N	\N	\N	\N	\N	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
\.


--
-- Data for Name: policy_results; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.policy_results (tenant_id, scan_id, asset_id, policy_pack_id, policy_pack_version, rule_id, verdict, offending_property, offending_value, explanation, source_reference, opa_input_hash, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:f5800e71638837602c2541e6487dd3d60ca76d7c4b947430bf1b39587a50992d	4e33ffeb-dc3e-48e4-95ea-e8da8af910b1	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:b955a225367395ee918a4c1c4429055f1f1e982ccd8115c5a6ba8e03a7b6137a	6f72a526-32e7-4471-9477-0c3e77b4ea61	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	pass	\N	\N	Passed rule verification.	\N	sha256:da1372c3fb83cdc460070aabd4a7cf049f6ffb33088aa242fb1cbada07de84f2	c576728f-59ee-4983-b8dc-a23a6d11b7ee	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:746ba115363d56a905b1a8d2a2e952ca21f4d85d23223a0efcc7189a0186d958	8d1e9720-76ba-4f18-afa6-fc0488197657	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:da2e113555b3f444e620962a94a1c0fd98c2369901830a9747fac06a54c903c5	a22294ef-6bc6-4b10-86a9-0e8ad12203b0	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	fail	algorithm	RSA	Classical public key algorithm is vulnerable to Shor's algorithm.	\N	sha256:3c291ecb654f3eb999eb79fca60e9881a65240e7ac524490c1679809832af079	82f46b6c-adf4-468c-8cd1-228b74ec31b2	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:d65c601f9ae4b69fab139fafa4ddab9cf49a65060369c938407eb5ad6c4e1cd6	e785186e-f160-4ce8-ba34-c296330f97fc	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:d588702e89a184654f2dfc97d11ecde3c749cee2f5ff8027e639f18d395b0b3e	70b30b94-1477-49c6-93e6-7b33cfec2a61	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	pass	\N	\N	Passed rule verification.	\N	sha256:ea3b9d062dabf8f5eee71aea4fd8a79ba75a10f9e79502c4ad7af6488d37612b	e1b17111-f1cd-4e72-92be-e6e4956d78df	2026-09-22 04:14:38.612236+00	2026-09-22 04:14:38.612236+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:f5800e71638837602c2541e6487dd3d60ca76d7c4b947430bf1b39587a50992d	fc7c8fa8-af4c-4daf-bb9d-c57187c91901	2026-09-22 04:17:03.822514+00	2026-09-22 04:17:03.822514+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:b955a225367395ee918a4c1c4429055f1f1e982ccd8115c5a6ba8e03a7b6137a	17bb6b57-4c54-42e5-b29f-35ae96ac0cd0	2026-09-22 04:17:03.822514+00	2026-09-22 04:17:03.822514+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	pass	\N	\N	Passed rule verification.	\N	sha256:da1372c3fb83cdc460070aabd4a7cf049f6ffb33088aa242fb1cbada07de84f2	d6353980-ad6d-4de9-bfeb-18910cf8c5ed	2026-09-22 04:17:03.822514+00	2026-09-22 04:17:03.822514+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:746ba115363d56a905b1a8d2a2e952ca21f4d85d23223a0efcc7189a0186d958	cbc4750a-6509-41db-9881-a355ef719016	2026-09-22 04:17:03.822514+00	2026-09-22 04:17:03.822514+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:da2e113555b3f444e620962a94a1c0fd98c2369901830a9747fac06a54c903c5	3af4eb0a-1381-49e0-b3aa-cfef50907302	2026-09-22 04:17:03.822514+00	2026-09-22 04:17:03.822514+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	fail	algorithm	RSA	Classical public key algorithm is vulnerable to Shor's algorithm.	\N	sha256:3c291ecb654f3eb999eb79fca60e9881a65240e7ac524490c1679809832af079	2d950735-cad6-4c4a-b869-bfa8ea54065d	2026-09-22 04:17:03.822514+00	2026-09-22 04:17:03.822514+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:d65c601f9ae4b69fab139fafa4ddab9cf49a65060369c938407eb5ad6c4e1cd6	3bde5b1d-dbd9-441d-b75c-a5d79b5c95c5	2026-09-22 04:17:03.822514+00	2026-09-22 04:17:03.822514+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:d588702e89a184654f2dfc97d11ecde3c749cee2f5ff8027e639f18d395b0b3e	b58ff6c5-3a43-4ae1-bc70-b2e359b8c692	2026-09-22 04:17:03.822514+00	2026-09-22 04:17:03.822514+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	pass	\N	\N	Passed rule verification.	\N	sha256:ea3b9d062dabf8f5eee71aea4fd8a79ba75a10f9e79502c4ad7af6488d37612b	5119b4b8-9f24-4b10-893f-d12e632ddc7b	2026-09-22 04:17:03.822514+00	2026-09-22 04:17:03.822514+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:f5800e71638837602c2541e6487dd3d60ca76d7c4b947430bf1b39587a50992d	a7f292e3-197a-4034-a8a4-ddb56146c58c	2026-09-22 16:42:36.889364+00	2026-09-22 16:42:36.889364+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:b955a225367395ee918a4c1c4429055f1f1e982ccd8115c5a6ba8e03a7b6137a	e69adcb9-b5dc-4c69-a519-e6c4b9ef7a7b	2026-09-22 16:42:36.889364+00	2026-09-22 16:42:36.889364+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	pass	\N	\N	Passed rule verification.	\N	sha256:da1372c3fb83cdc460070aabd4a7cf049f6ffb33088aa242fb1cbada07de84f2	72099c29-5291-4d41-98a1-329a6854d249	2026-09-22 16:42:36.889364+00	2026-09-22 16:42:36.889364+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:746ba115363d56a905b1a8d2a2e952ca21f4d85d23223a0efcc7189a0186d958	1570f627-bce7-4a39-af25-2f851395811d	2026-09-22 16:42:36.889364+00	2026-09-22 16:42:36.889364+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:da2e113555b3f444e620962a94a1c0fd98c2369901830a9747fac06a54c903c5	a8a50a68-bd76-4b04-8760-54e6bf90843b	2026-09-22 16:42:36.889364+00	2026-09-22 16:42:36.889364+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	fail	algorithm	RSA	Classical public key algorithm is vulnerable to Shor's algorithm.	\N	sha256:3c291ecb654f3eb999eb79fca60e9881a65240e7ac524490c1679809832af079	df5f683d-25ad-46ea-a5ca-87696568ca53	2026-09-22 16:42:36.889364+00	2026-09-22 16:42:36.889364+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:d65c601f9ae4b69fab139fafa4ddab9cf49a65060369c938407eb5ad6c4e1cd6	92fa0c33-da8a-4dca-a86d-81eed7f27c8c	2026-09-22 16:42:36.889364+00	2026-09-22 16:42:36.889364+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:d588702e89a184654f2dfc97d11ecde3c749cee2f5ff8027e639f18d395b0b3e	f5917f5d-5930-4d63-9a4f-e3d0b2b5d3a9	2026-09-22 16:42:36.889364+00	2026-09-22 16:42:36.889364+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	pass	\N	\N	Passed rule verification.	\N	sha256:ea3b9d062dabf8f5eee71aea4fd8a79ba75a10f9e79502c4ad7af6488d37612b	a3a621fd-d71e-4db5-b1b9-c0ec992aac6a	2026-09-22 16:42:36.889364+00	2026-09-22 16:42:36.889364+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:f5800e71638837602c2541e6487dd3d60ca76d7c4b947430bf1b39587a50992d	a81c1fcc-3502-408e-b0b8-4d4309e5d24a	2026-09-22 16:44:04.01204+00	2026-09-22 16:44:04.01204+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:b955a225367395ee918a4c1c4429055f1f1e982ccd8115c5a6ba8e03a7b6137a	e1aa2261-98fc-409d-9802-af7579e27d65	2026-09-22 16:44:04.01204+00	2026-09-22 16:44:04.01204+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	514541ce-a2e7-41d7-9e66-152e3d63da8a	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	pass	\N	\N	Passed rule verification.	\N	sha256:da1372c3fb83cdc460070aabd4a7cf049f6ffb33088aa242fb1cbada07de84f2	7a423302-402e-411f-8580-7251c4161740	2026-09-22 16:44:04.01204+00	2026-09-22 16:44:04.01204+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:746ba115363d56a905b1a8d2a2e952ca21f4d85d23223a0efcc7189a0186d958	e4107d98-5dfc-4a76-82a0-90c8bed14615	2026-09-22 16:44:04.01204+00	2026-09-22 16:44:04.01204+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:da2e113555b3f444e620962a94a1c0fd98c2369901830a9747fac06a54c903c5	8320068d-746a-44ca-956f-56c62f930eb1	2026-09-22 16:44:04.01204+00	2026-09-22 16:44:04.01204+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	5150438b-3602-4908-8dc5-d5c154592a00	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	fail	algorithm	RSA	Classical public key algorithm is vulnerable to Shor's algorithm.	\N	sha256:3c291ecb654f3eb999eb79fca60e9881a65240e7ac524490c1679809832af079	5a0a7085-b56c-4050-afb1-243512652621	2026-09-22 16:44:04.01204+00	2026-09-22 16:44:04.01204+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-LEGACY-001	pass	\N	\N	Passed rule verification.	\N	sha256:d65c601f9ae4b69fab139fafa4ddab9cf49a65060369c938407eb5ad6c4e1cd6	d7b2265f-6303-42bc-9cbd-2588c916e74f	2026-09-22 16:44:04.01204+00	2026-09-22 16:44:04.01204+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	CRYPTO-RSA-001	pass	\N	\N	Passed rule verification.	\N	sha256:d588702e89a184654f2dfc97d11ecde3c749cee2f5ff8027e639f18d395b0b3e	f0a006b9-1d92-4a51-a963-b0cc3ea73f41	2026-09-22 16:44:04.01204+00	2026-09-22 16:44:04.01204+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	b0d8844a-aec9-47a8-b526-a242718ab205	2cf0a349-aace-5a69-98d5-dd021b9c1bf8	1.0	PQC-MIGRATION-001	pass	\N	\N	Passed rule verification.	\N	sha256:ea3b9d062dabf8f5eee71aea4fd8a79ba75a10f9e79502c4ad7af6488d37612b	e3fdbf0a-2ac0-4d43-ae10-0785c4981bd6	2026-09-22 16:44:04.01204+00	2026-09-22 16:44:04.01204+00
\.


--
-- Data for Name: policy_rules; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.policy_rules (pack_id, rule_id, version, name, description, severity, rego_package, source_reference, conditions, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: relationships; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.relationships (tenant_id, relationship_type, from_id, from_type, to_id, to_type, metadata, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: repositories; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.repositories (tenant_id, name, url, vcs_type, default_branch, language, metadata, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	payment-gateway-service	\N	\N	main	multi	{"auto_provisioned": true}	656af2f9-d7a2-4831-9237-2707b912a603	2026-09-22 03:50:45.705975+00	2026-09-22 03:50:45.705979+00
\.


--
-- Data for Name: risk_assessments; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.risk_assessments (tenant_id, asset_id, scan_id, risk_profile_id, risk_profile_version, x_value, x_source, x_source_version, x_override, y_value, y_min, y_max, y_source, y_assumption, mosca_results, qars_temporal, qars_sensitivity, qars_exposure, qars_score, original_qars_score, override_score, override_reason, override_reviewer, override_at, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	514541ce-a2e7-41d7-9e66-152e3d63da8a	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	1.0	10	default_conservative	\N	f	3	1	5	migration_estimate_v1.0	\N	{"y_max": 5.0, "y_min": 1.0, "x_value": 10.0, "y_value": 3.0, "x_source": "default_conservative", "y_source": "migration_estimate_v1.0", "scenarios": [{"label": "conservative", "result": 8.0, "verdict": "act_now", "z_years": 5.0, "margin_years": 8.0}, {"label": "central", "result": 3.0, "verdict": "act_now", "z_years": 10.0, "margin_years": 3.0}, {"label": "optimistic", "result": -2.0, "verdict": "monitor", "z_years": 15.0, "margin_years": 2.0}], "z_central": 10.0, "z_optimistic": 15.0, "z_conservative": 5.0}	1	0.5	0.5	0.6666	\N	\N	\N	\N	\N	aecd941a-dd76-4009-a4b8-094bdfd941b9	2026-09-22 04:17:03.805074+00	2026-09-22 04:17:03.805074+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	5150438b-3602-4908-8dc5-d5c154592a00	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	1.0	10	default_conservative	\N	f	3	1	5	migration_estimate_v1.0	\N	{"y_max": 5.0, "y_min": 1.0, "x_value": 10.0, "y_value": 3.0, "x_source": "default_conservative", "y_source": "migration_estimate_v1.0", "scenarios": [{"label": "conservative", "result": 8.0, "verdict": "act_now", "z_years": 5.0, "margin_years": 8.0}, {"label": "central", "result": 3.0, "verdict": "act_now", "z_years": 10.0, "margin_years": 3.0}, {"label": "optimistic", "result": -2.0, "verdict": "monitor", "z_years": 15.0, "margin_years": 2.0}], "z_central": 10.0, "z_optimistic": 15.0, "z_conservative": 5.0}	1	0.5	0.5	0.6666	\N	\N	\N	\N	\N	c47e68bf-815d-45df-b4e4-8de928608939	2026-09-22 04:17:03.805074+00	2026-09-22 04:17:03.805074+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	b0d8844a-aec9-47a8-b526-a242718ab205	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	1.0	10	default_conservative	\N	f	3	1	5	migration_estimate_v1.0	\N	{"y_max": 5.0, "y_min": 1.0, "x_value": 10.0, "y_value": 3.0, "x_source": "default_conservative", "y_source": "migration_estimate_v1.0", "scenarios": [{"label": "conservative", "result": 8.0, "verdict": "act_now", "z_years": 5.0, "margin_years": 8.0}, {"label": "central", "result": 3.0, "verdict": "act_now", "z_years": 10.0, "margin_years": 3.0}, {"label": "optimistic", "result": -2.0, "verdict": "monitor", "z_years": 15.0, "margin_years": 2.0}], "z_central": 10.0, "z_optimistic": 15.0, "z_conservative": 5.0}	1	0.5	0.5	0.6666	\N	\N	\N	\N	\N	23b6f606-b2a9-42e6-8aff-d77785faecae	2026-09-22 04:17:03.805074+00	2026-09-22 04:17:03.805074+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	514541ce-a2e7-41d7-9e66-152e3d63da8a	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	1.0	10	default_conservative	\N	f	3	1	5	migration_estimate_v1.0	\N	{"y_max": 5.0, "y_min": 1.0, "x_value": 10.0, "y_value": 3.0, "x_source": "default_conservative", "y_source": "migration_estimate_v1.0", "scenarios": [{"label": "conservative", "result": 8.0, "verdict": "act_now", "z_years": 5.0, "margin_years": 8.0}, {"label": "central", "result": 3.0, "verdict": "act_now", "z_years": 10.0, "margin_years": 3.0}, {"label": "optimistic", "result": -2.0, "verdict": "monitor", "z_years": 15.0, "margin_years": 2.0}], "z_central": 10.0, "z_optimistic": 15.0, "z_conservative": 5.0}	1	0.5	0.5	0.6666	\N	\N	\N	\N	\N	34a9ff36-fef4-4d63-a40d-ca5377c80f5b	2026-09-22 16:42:36.615954+00	2026-09-22 16:42:36.615954+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	5150438b-3602-4908-8dc5-d5c154592a00	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	1.0	10	default_conservative	\N	f	3	1	5	migration_estimate_v1.0	\N	{"y_max": 5.0, "y_min": 1.0, "x_value": 10.0, "y_value": 3.0, "x_source": "default_conservative", "y_source": "migration_estimate_v1.0", "scenarios": [{"label": "conservative", "result": 8.0, "verdict": "act_now", "z_years": 5.0, "margin_years": 8.0}, {"label": "central", "result": 3.0, "verdict": "act_now", "z_years": 10.0, "margin_years": 3.0}, {"label": "optimistic", "result": -2.0, "verdict": "monitor", "z_years": 15.0, "margin_years": 2.0}], "z_central": 10.0, "z_optimistic": 15.0, "z_conservative": 5.0}	1	0.5	0.5	0.6666	\N	\N	\N	\N	\N	7a2ec097-81b2-49ea-99f5-2e68ccf2c113	2026-09-22 16:42:36.615954+00	2026-09-22 16:42:36.615954+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	b0d8844a-aec9-47a8-b526-a242718ab205	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	1.0	10	default_conservative	\N	f	3	1	5	migration_estimate_v1.0	\N	{"y_max": 5.0, "y_min": 1.0, "x_value": 10.0, "y_value": 3.0, "x_source": "default_conservative", "y_source": "migration_estimate_v1.0", "scenarios": [{"label": "conservative", "result": 8.0, "verdict": "act_now", "z_years": 5.0, "margin_years": 8.0}, {"label": "central", "result": 3.0, "verdict": "act_now", "z_years": 10.0, "margin_years": 3.0}, {"label": "optimistic", "result": -2.0, "verdict": "monitor", "z_years": 15.0, "margin_years": 2.0}], "z_central": 10.0, "z_optimistic": 15.0, "z_conservative": 5.0}	1	0.5	0.5	0.6666	\N	\N	\N	\N	\N	526a514c-740e-4241-af12-517bced14c18	2026-09-22 16:42:36.615954+00	2026-09-22 16:42:36.615954+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	514541ce-a2e7-41d7-9e66-152e3d63da8a	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	1.0	10	default_conservative	\N	f	3	1	5	migration_estimate_v1.0	\N	{"y_max": 5.0, "y_min": 1.0, "x_value": 10.0, "y_value": 3.0, "x_source": "default_conservative", "y_source": "migration_estimate_v1.0", "scenarios": [{"label": "conservative", "result": 8.0, "verdict": "act_now", "z_years": 5.0, "margin_years": 8.0}, {"label": "central", "result": 3.0, "verdict": "act_now", "z_years": 10.0, "margin_years": 3.0}, {"label": "optimistic", "result": -2.0, "verdict": "monitor", "z_years": 15.0, "margin_years": 2.0}], "z_central": 10.0, "z_optimistic": 15.0, "z_conservative": 5.0}	1	0.5	0.5	0.6666	\N	\N	\N	\N	\N	0f91faef-f88c-432a-9a0d-c13bc8ff564f	2026-09-22 16:44:03.793864+00	2026-09-22 16:44:03.793864+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	5150438b-3602-4908-8dc5-d5c154592a00	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	1.0	10	default_conservative	\N	f	3	1	5	migration_estimate_v1.0	\N	{"y_max": 5.0, "y_min": 1.0, "x_value": 10.0, "y_value": 3.0, "x_source": "default_conservative", "y_source": "migration_estimate_v1.0", "scenarios": [{"label": "conservative", "result": 8.0, "verdict": "act_now", "z_years": 5.0, "margin_years": 8.0}, {"label": "central", "result": 3.0, "verdict": "act_now", "z_years": 10.0, "margin_years": 3.0}, {"label": "optimistic", "result": -2.0, "verdict": "monitor", "z_years": 15.0, "margin_years": 2.0}], "z_central": 10.0, "z_optimistic": 15.0, "z_conservative": 5.0}	1	0.5	0.5	0.6666	\N	\N	\N	\N	\N	a7c0ce51-6349-4e64-a4a5-076254890979	2026-09-22 16:44:03.793864+00	2026-09-22 16:44:03.793864+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	b0d8844a-aec9-47a8-b526-a242718ab205	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	1.0	10	default_conservative	\N	f	3	1	5	migration_estimate_v1.0	\N	{"y_max": 5.0, "y_min": 1.0, "x_value": 10.0, "y_value": 3.0, "x_source": "default_conservative", "y_source": "migration_estimate_v1.0", "scenarios": [{"label": "conservative", "result": 8.0, "verdict": "act_now", "z_years": 5.0, "margin_years": 8.0}, {"label": "central", "result": 3.0, "verdict": "act_now", "z_years": 10.0, "margin_years": 3.0}, {"label": "optimistic", "result": -2.0, "verdict": "monitor", "z_years": 15.0, "margin_years": 2.0}], "z_central": 10.0, "z_optimistic": 15.0, "z_conservative": 5.0}	1	0.5	0.5	0.6666	\N	\N	\N	\N	\N	695de3b7-eaa4-4102-88fb-26da29cfbdee	2026-09-22 16:44:03.793864+00	2026-09-22 16:44:03.793864+00
\.


--
-- Data for Name: risk_profiles; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.risk_profiles (tenant_id, version, name, is_active, weight_temporal, weight_sensitivity, weight_exposure, x_default_years, y_default_years, metadata, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	1.0	Default Enterprise Risk Profile	t	0.3333	0.3333	0.3334	\N	\N	{}	1e5d1f2b-83ca-5268-bfdf-65cf67b073ad	2026-09-22 04:12:23.126401+00	2026-09-22 04:12:23.126401+00
\.


--
-- Data for Name: scans; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.scans (tenant_id, repository_id, commit_ref, input_revision, status, started_at, completed_at, canonical_model_version, scan_configuration, is_complete, completeness_summary, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	RUNNING	2026-09-22 03:50:46.164228+00	\N	1.0	{"requested_collectors": "all"}	f	{}	c51fe79c-a401-4d54-8001-456d65442e98	2026-09-22 03:50:45.707035+00	2026-09-22 03:50:45.707038+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	RUNNING	2026-09-22 03:52:26.079616+00	\N	1.0	{"requested_collectors": "all"}	f	{}	a1b341a0-deb5-450e-b363-066fed45ef60	2026-09-22 03:52:25.081817+00	2026-09-22 03:52:25.081821+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	RUNNING	2026-09-22 03:54:55.90332+00	\N	1.0	{"requested_collectors": "all"}	f	{}	9f008610-d735-47d9-80a3-3a52020c90f0	2026-09-22 03:54:55.633942+00	2026-09-22 03:54:55.633946+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	RUNNING	2026-09-22 04:08:24.9548+00	\N	1.0	{"requested_collectors": "all"}	f	{}	024b13c4-3c2b-41bb-aa55-502939749cb0	2026-09-22 04:08:24.643239+00	2026-09-22 04:08:24.643257+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	RUNNING	2026-09-22 04:09:40.014912+00	\N	1.0	{"requested_collectors": "all"}	f	{}	55b8a79d-a57c-4410-82fd-dcf19e933127	2026-09-22 04:09:39.050319+00	2026-09-22 04:09:39.050323+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	RUNNING	2026-09-22 04:10:23.443857+00	\N	1.0	{"requested_collectors": "all"}	f	{}	96294047-e987-41b3-9237-686a7f32368c	2026-09-22 04:10:22.6792+00	2026-09-22 04:10:22.679205+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	RUNNING	2026-09-22 04:11:01.272962+00	\N	1.0	{"requested_collectors": "all"}	f	{}	816d9cad-340f-4d0f-8b8b-f92b74d88711	2026-09-22 04:11:00.326553+00	2026-09-22 04:11:00.326556+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	RUNNING	2026-09-22 04:12:22.56109+00	\N	1.0	{"requested_collectors": "all"}	f	{}	f0e737fc-0460-4398-9493-42c4c3279e82	2026-09-22 04:12:21.799081+00	2026-09-22 04:12:21.799086+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	COMPLETE	2026-09-22 04:14:37.784076+00	2026-09-22 04:14:38.786742+00	1.0	{"requested_collectors": "all"}	t	{}	690dbd77-e499-4a4d-8f4a-ed301b8624d2	2026-09-22 04:14:37.271017+00	2026-09-22 04:14:37.27102+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	COMPLETE	2026-09-22 04:17:03.703902+00	2026-09-22 04:17:03.869487+00	1.0	{"requested_collectors": "all"}	t	{}	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	2026-09-22 04:17:03.495203+00	2026-09-22 04:17:03.495207+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	COMPLETE	2026-09-22 16:42:35.055117+00	2026-09-22 16:42:37.206445+00	1.0	{"requested_collectors": "all"}	t	{}	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	2026-09-22 16:42:34.822016+00	2026-09-22 16:42:34.822026+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	656af2f9-d7a2-4831-9237-2707b912a603	main	\N	COMPLETE	2026-09-22 16:44:03.674929+00	2026-09-22 16:44:04.051009+00	1.0	{"requested_collectors": "all"}	t	{}	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	2026-09-22 16:44:03.009545+00	2026-09-22 16:44:03.009548+00
\.


--
-- Data for Name: snapshots; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.snapshots (tenant_id, scan_id, canonical_hash, merkle_root, tsa_url, tsa_timestamp_at, tsa_token_hash, tsa_token_uri, canonical_model_version, policy_pack_versions, risk_profile_version, advisory_version, merkle_tree_uri, is_verified, verified_at, id, created_at, updated_at) FROM stdin;
19e7e44b-6d63-4c16-9ef7-701b266550a7	690dbd77-e499-4a4d-8f4a-ed301b8624d2	f1018f37e08f2d2b4f3dc0617fd7a12de9da553b6b2a5f06e7358504518621f2	d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4	\N	\N	\N	\N	1.0	{}	1.0	1.0	inline:{"root": "d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4", "leaf_count": 3, "leaf_hashes": ["93ff67e3cf32eee0535332306224ad8ed75ba4080d5dc0ee4245b1e1bf5b8b3a", "f0fc81ba27bf82cfbf610a360c471c35d557bdea79b29d4f661c89550611b0e5", "0e9c80bef9bc87e89c23b90cd2e09087c154ccbab0ca47fae0644021c1697e04"], "levels": [["93ff67e3cf32eee0535332306224ad8ed75ba4080d5dc0ee4245b1e1bf5b8b3a", "f0fc81ba27bf82cfbf610a360c471c35d557bdea79b29d4f661c89550611b0e5", "0e9c80bef9bc87e89c23b90cd2e09087c154ccbab0ca47fae0644021c1697e04"], ["1cdb8e58b7cf21d56ed4ef6f64109c4ccc2787a9a8861448fe69092628c342ee", "234a7ffa428751f15616a891dcb7824a5cd540d6878aa2adc2e7c19c8a7cc8b2"], ["d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4"]]}	t	2026-09-22 04:14:38.778145+00	3bd2326d-cdb7-45ed-b861-c758b1d9be4d	2026-09-22 04:14:38.778145+00	2026-09-22 04:14:38.778145+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	e07f0f3e-4ee5-4c10-bb2b-fe31f32aa2d8	f1018f37e08f2d2b4f3dc0617fd7a12de9da553b6b2a5f06e7358504518621f2	d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4	\N	\N	\N	\N	1.0	{}	1.0	1.0	inline:{"root": "d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4", "leaf_count": 3, "leaf_hashes": ["93ff67e3cf32eee0535332306224ad8ed75ba4080d5dc0ee4245b1e1bf5b8b3a", "f0fc81ba27bf82cfbf610a360c471c35d557bdea79b29d4f661c89550611b0e5", "0e9c80bef9bc87e89c23b90cd2e09087c154ccbab0ca47fae0644021c1697e04"], "levels": [["93ff67e3cf32eee0535332306224ad8ed75ba4080d5dc0ee4245b1e1bf5b8b3a", "f0fc81ba27bf82cfbf610a360c471c35d557bdea79b29d4f661c89550611b0e5", "0e9c80bef9bc87e89c23b90cd2e09087c154ccbab0ca47fae0644021c1697e04"], ["1cdb8e58b7cf21d56ed4ef6f64109c4ccc2787a9a8861448fe69092628c342ee", "234a7ffa428751f15616a891dcb7824a5cd540d6878aa2adc2e7c19c8a7cc8b2"], ["d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4"]]}	t	2026-09-22 04:17:03.862861+00	4ab222f8-1349-4dbb-ae6b-4d8d3c17dc49	2026-09-22 04:17:03.862861+00	2026-09-22 04:17:03.862861+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	7bcc5ead-dd89-450f-a7a5-c58747fdc9a2	f1018f37e08f2d2b4f3dc0617fd7a12de9da553b6b2a5f06e7358504518621f2	d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4	\N	\N	\N	\N	1.0	{}	1.0	1.0	inline:{"root": "d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4", "leaf_count": 3, "leaf_hashes": ["93ff67e3cf32eee0535332306224ad8ed75ba4080d5dc0ee4245b1e1bf5b8b3a", "f0fc81ba27bf82cfbf610a360c471c35d557bdea79b29d4f661c89550611b0e5", "0e9c80bef9bc87e89c23b90cd2e09087c154ccbab0ca47fae0644021c1697e04"], "levels": [["93ff67e3cf32eee0535332306224ad8ed75ba4080d5dc0ee4245b1e1bf5b8b3a", "f0fc81ba27bf82cfbf610a360c471c35d557bdea79b29d4f661c89550611b0e5", "0e9c80bef9bc87e89c23b90cd2e09087c154ccbab0ca47fae0644021c1697e04"], ["1cdb8e58b7cf21d56ed4ef6f64109c4ccc2787a9a8861448fe69092628c342ee", "234a7ffa428751f15616a891dcb7824a5cd540d6878aa2adc2e7c19c8a7cc8b2"], ["d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4"]]}	t	2026-09-22 16:42:37.195856+00	81ef1644-169b-4b13-82e0-6d7577e02900	2026-09-22 16:42:37.195856+00	2026-09-22 16:42:37.195856+00
19e7e44b-6d63-4c16-9ef7-701b266550a7	40fe6196-d1ed-4b6c-a0df-b9ef84e721af	f1018f37e08f2d2b4f3dc0617fd7a12de9da553b6b2a5f06e7358504518621f2	d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4	\N	\N	\N	\N	1.0	{}	1.0	1.0	inline:{"root": "d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4", "leaf_count": 3, "leaf_hashes": ["93ff67e3cf32eee0535332306224ad8ed75ba4080d5dc0ee4245b1e1bf5b8b3a", "f0fc81ba27bf82cfbf610a360c471c35d557bdea79b29d4f661c89550611b0e5", "0e9c80bef9bc87e89c23b90cd2e09087c154ccbab0ca47fae0644021c1697e04"], "levels": [["93ff67e3cf32eee0535332306224ad8ed75ba4080d5dc0ee4245b1e1bf5b8b3a", "f0fc81ba27bf82cfbf610a360c471c35d557bdea79b29d4f661c89550611b0e5", "0e9c80bef9bc87e89c23b90cd2e09087c154ccbab0ca47fae0644021c1697e04"], ["1cdb8e58b7cf21d56ed4ef6f64109c4ccc2787a9a8861448fe69092628c342ee", "234a7ffa428751f15616a891dcb7824a5cd540d6878aa2adc2e7c19c8a7cc8b2"], ["d337a970757596b25638d0c435f4e6e9e22c56cd8263cbf03cacdfa6b60721f4"]]}	t	2026-09-22 16:44:04.013122+00	1a78fa11-4d09-411f-84da-181dae1b69ac	2026-09-22 16:44:04.013122+00	2026-09-22 16:44:04.013122+00
\.


--
-- Data for Name: tenants; Type: TABLE DATA; Schema: public; Owner: ecdat
--

COPY public.tenants (name, display_name, is_active, settings, id, created_at, updated_at) FROM stdin;
default-enterprise	Enterprise Cryptographic Estate	t	{}	19e7e44b-6d63-4c16-9ef7-701b266550a7	2026-09-22 03:50:45.705063+00	2026-09-22 03:50:45.705067+00
\.


--
-- Name: advisory_families advisory_families_name_key; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.advisory_families
    ADD CONSTRAINT advisory_families_name_key UNIQUE (name);


--
-- Name: advisory_families advisory_families_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.advisory_families
    ADD CONSTRAINT advisory_families_pkey PRIMARY KEY (id);


--
-- Name: advisory_mappings advisory_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.advisory_mappings
    ADD CONSTRAINT advisory_mappings_pkey PRIMARY KEY (id);


--
-- Name: advisory_variants advisory_variants_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.advisory_variants
    ADD CONSTRAINT advisory_variants_pkey PRIMARY KEY (id);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: collector_runs collector_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.collector_runs
    ADD CONSTRAINT collector_runs_pkey PRIMARY KEY (id);


--
-- Name: components components_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.components
    ADD CONSTRAINT components_pkey PRIMARY KEY (id);


--
-- Name: conflict_records conflict_records_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.conflict_records
    ADD CONSTRAINT conflict_records_pkey PRIMARY KEY (id);


--
-- Name: dead_letter_events dead_letter_events_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.dead_letter_events
    ADD CONSTRAINT dead_letter_events_pkey PRIMARY KEY (id);


--
-- Name: evidence evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_pkey PRIMARY KEY (id);


--
-- Name: exemptions exemptions_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.exemptions
    ADD CONSTRAINT exemptions_pkey PRIMARY KEY (id);


--
-- Name: job_attempts job_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.job_attempts
    ADD CONSTRAINT job_attempts_pkey PRIMARY KEY (id);


--
-- Name: job_events job_events_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.job_events
    ADD CONSTRAINT job_events_pkey PRIMARY KEY (id);


--
-- Name: jobs jobs_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: jobs jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_pkey PRIMARY KEY (id);


--
-- Name: occurrences occurrences_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.occurrences
    ADD CONSTRAINT occurrences_pkey PRIMARY KEY (id);


--
-- Name: policy_packs policy_packs_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.policy_packs
    ADD CONSTRAINT policy_packs_pkey PRIMARY KEY (id);


--
-- Name: policy_results policy_results_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.policy_results
    ADD CONSTRAINT policy_results_pkey PRIMARY KEY (id);


--
-- Name: policy_rules policy_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.policy_rules
    ADD CONSTRAINT policy_rules_pkey PRIMARY KEY (id);


--
-- Name: relationships relationships_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.relationships
    ADD CONSTRAINT relationships_pkey PRIMARY KEY (id);


--
-- Name: repositories repositories_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.repositories
    ADD CONSTRAINT repositories_pkey PRIMARY KEY (id);


--
-- Name: risk_assessments risk_assessments_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.risk_assessments
    ADD CONSTRAINT risk_assessments_pkey PRIMARY KEY (id);


--
-- Name: risk_profiles risk_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.risk_profiles
    ADD CONSTRAINT risk_profiles_pkey PRIMARY KEY (id);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: snapshots snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.snapshots
    ADD CONSTRAINT snapshots_pkey PRIMARY KEY (id);


--
-- Name: tenants tenants_name_key; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_name_key UNIQUE (name);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: ix_advisory_mappings_from_primitive; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_advisory_mappings_from_primitive ON public.advisory_mappings USING btree (from_primitive);


--
-- Name: ix_advisory_variants_family_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_advisory_variants_family_id ON public.advisory_variants USING btree (family_id);


--
-- Name: ix_assets_algorithm; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_assets_algorithm ON public.assets USING btree (algorithm);


--
-- Name: ix_assets_confidence; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_assets_confidence ON public.assets USING btree (confidence);


--
-- Name: ix_assets_stable_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_assets_stable_id ON public.assets USING btree (stable_id);


--
-- Name: ix_assets_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_assets_tenant_id ON public.assets USING btree (tenant_id);


--
-- Name: ix_audit_events_event_type; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_audit_events_event_type ON public.audit_events USING btree (event_type);


--
-- Name: ix_audit_events_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_audit_events_tenant_id ON public.audit_events USING btree (tenant_id);


--
-- Name: ix_collector_runs_scan_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_collector_runs_scan_id ON public.collector_runs USING btree (scan_id);


--
-- Name: ix_collector_runs_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_collector_runs_tenant_id ON public.collector_runs USING btree (tenant_id);


--
-- Name: ix_components_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_components_tenant_id ON public.components USING btree (tenant_id);


--
-- Name: ix_conflict_records_asset_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_conflict_records_asset_id ON public.conflict_records USING btree (asset_id);


--
-- Name: ix_conflict_records_resolution_state; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_conflict_records_resolution_state ON public.conflict_records USING btree (resolution_state);


--
-- Name: ix_conflict_records_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_conflict_records_tenant_id ON public.conflict_records USING btree (tenant_id);


--
-- Name: ix_dead_letter_events_job_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_dead_letter_events_job_id ON public.dead_letter_events USING btree (job_id);


--
-- Name: ix_dead_letter_events_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_dead_letter_events_tenant_id ON public.dead_letter_events USING btree (tenant_id);


--
-- Name: ix_evidence_occurrence_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_evidence_occurrence_id ON public.evidence USING btree (occurrence_id);


--
-- Name: ix_evidence_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_evidence_tenant_id ON public.evidence USING btree (tenant_id);


--
-- Name: ix_exemptions_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_exemptions_tenant_id ON public.exemptions USING btree (tenant_id);


--
-- Name: ix_job_attempts_job_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_job_attempts_job_id ON public.job_attempts USING btree (job_id);


--
-- Name: ix_job_events_job_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_job_events_job_id ON public.job_events USING btree (job_id);


--
-- Name: ix_jobs_job_type; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_jobs_job_type ON public.jobs USING btree (job_type);


--
-- Name: ix_jobs_scan_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_jobs_scan_id ON public.jobs USING btree (scan_id);


--
-- Name: ix_jobs_state; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_jobs_state ON public.jobs USING btree (state);


--
-- Name: ix_jobs_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_jobs_tenant_id ON public.jobs USING btree (tenant_id);


--
-- Name: ix_occurrences_asset_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_occurrences_asset_id ON public.occurrences USING btree (asset_id);


--
-- Name: ix_occurrences_scan_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_occurrences_scan_id ON public.occurrences USING btree (scan_id);


--
-- Name: ix_occurrences_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_occurrences_tenant_id ON public.occurrences USING btree (tenant_id);


--
-- Name: ix_policy_packs_status; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_policy_packs_status ON public.policy_packs USING btree (status);


--
-- Name: ix_policy_packs_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_policy_packs_tenant_id ON public.policy_packs USING btree (tenant_id);


--
-- Name: ix_policy_results_asset_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_policy_results_asset_id ON public.policy_results USING btree (asset_id);


--
-- Name: ix_policy_results_scan_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_policy_results_scan_id ON public.policy_results USING btree (scan_id);


--
-- Name: ix_policy_results_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_policy_results_tenant_id ON public.policy_results USING btree (tenant_id);


--
-- Name: ix_policy_results_verdict; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_policy_results_verdict ON public.policy_results USING btree (verdict);


--
-- Name: ix_policy_rules_pack_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_policy_rules_pack_id ON public.policy_rules USING btree (pack_id);


--
-- Name: ix_relationships_from_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_relationships_from_id ON public.relationships USING btree (from_id);


--
-- Name: ix_relationships_relationship_type; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_relationships_relationship_type ON public.relationships USING btree (relationship_type);


--
-- Name: ix_relationships_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_relationships_tenant_id ON public.relationships USING btree (tenant_id);


--
-- Name: ix_relationships_to_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_relationships_to_id ON public.relationships USING btree (to_id);


--
-- Name: ix_repositories_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_repositories_tenant_id ON public.repositories USING btree (tenant_id);


--
-- Name: ix_risk_assessments_asset_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_risk_assessments_asset_id ON public.risk_assessments USING btree (asset_id);


--
-- Name: ix_risk_assessments_qars_score; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_risk_assessments_qars_score ON public.risk_assessments USING btree (qars_score);


--
-- Name: ix_risk_assessments_scan_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_risk_assessments_scan_id ON public.risk_assessments USING btree (scan_id);


--
-- Name: ix_risk_assessments_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_risk_assessments_tenant_id ON public.risk_assessments USING btree (tenant_id);


--
-- Name: ix_risk_profiles_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_risk_profiles_tenant_id ON public.risk_profiles USING btree (tenant_id);


--
-- Name: ix_scans_repository_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_scans_repository_id ON public.scans USING btree (repository_id);


--
-- Name: ix_scans_status; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_scans_status ON public.scans USING btree (status);


--
-- Name: ix_scans_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_scans_tenant_id ON public.scans USING btree (tenant_id);


--
-- Name: ix_snapshots_scan_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_snapshots_scan_id ON public.snapshots USING btree (scan_id);


--
-- Name: ix_snapshots_tenant_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE INDEX ix_snapshots_tenant_id ON public.snapshots USING btree (tenant_id);


--
-- Name: uq_assets_stable_id; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE UNIQUE INDEX uq_assets_stable_id ON public.assets USING btree (stable_id);


--
-- Name: uq_risk_assessments_asset_scan; Type: INDEX; Schema: public; Owner: ecdat
--

CREATE UNIQUE INDEX uq_risk_assessments_asset_scan ON public.risk_assessments USING btree (asset_id, scan_id);


--
-- Name: advisory_mappings advisory_mappings_to_family_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.advisory_mappings
    ADD CONSTRAINT advisory_mappings_to_family_id_fkey FOREIGN KEY (to_family_id) REFERENCES public.advisory_families(id);


--
-- Name: advisory_mappings advisory_mappings_to_variant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.advisory_mappings
    ADD CONSTRAINT advisory_mappings_to_variant_id_fkey FOREIGN KEY (to_variant_id) REFERENCES public.advisory_variants(id);


--
-- Name: advisory_variants advisory_variants_family_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.advisory_variants
    ADD CONSTRAINT advisory_variants_family_id_fkey FOREIGN KEY (family_id) REFERENCES public.advisory_families(id) ON DELETE CASCADE;


--
-- Name: assets assets_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: audit_events audit_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: collector_runs collector_runs_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.collector_runs
    ADD CONSTRAINT collector_runs_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: collector_runs collector_runs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.collector_runs
    ADD CONSTRAINT collector_runs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: components components_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.components
    ADD CONSTRAINT components_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: conflict_records conflict_records_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.conflict_records
    ADD CONSTRAINT conflict_records_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id);


--
-- Name: conflict_records conflict_records_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.conflict_records
    ADD CONSTRAINT conflict_records_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: evidence evidence_occurrence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_occurrence_id_fkey FOREIGN KEY (occurrence_id) REFERENCES public.occurrences(id) ON DELETE CASCADE;


--
-- Name: evidence evidence_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: exemptions exemptions_policy_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.exemptions
    ADD CONSTRAINT exemptions_policy_result_id_fkey FOREIGN KEY (policy_result_id) REFERENCES public.policy_results(id) ON DELETE SET NULL;


--
-- Name: exemptions exemptions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.exemptions
    ADD CONSTRAINT exemptions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: job_attempts job_attempts_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.job_attempts
    ADD CONSTRAINT job_attempts_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.jobs(id) ON DELETE CASCADE;


--
-- Name: jobs jobs_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: jobs jobs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: occurrences occurrences_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.occurrences
    ADD CONSTRAINT occurrences_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: occurrences occurrences_collector_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.occurrences
    ADD CONSTRAINT occurrences_collector_run_id_fkey FOREIGN KEY (collector_run_id) REFERENCES public.collector_runs(id) ON DELETE SET NULL;


--
-- Name: occurrences occurrences_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.occurrences
    ADD CONSTRAINT occurrences_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: occurrences occurrences_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.occurrences
    ADD CONSTRAINT occurrences_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: policy_packs policy_packs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.policy_packs
    ADD CONSTRAINT policy_packs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: policy_results policy_results_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.policy_results
    ADD CONSTRAINT policy_results_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: policy_results policy_results_policy_pack_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.policy_results
    ADD CONSTRAINT policy_results_policy_pack_id_fkey FOREIGN KEY (policy_pack_id) REFERENCES public.policy_packs(id);


--
-- Name: policy_results policy_results_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.policy_results
    ADD CONSTRAINT policy_results_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: policy_results policy_results_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.policy_results
    ADD CONSTRAINT policy_results_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: policy_rules policy_rules_pack_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.policy_rules
    ADD CONSTRAINT policy_rules_pack_id_fkey FOREIGN KEY (pack_id) REFERENCES public.policy_packs(id) ON DELETE CASCADE;


--
-- Name: relationships relationships_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.relationships
    ADD CONSTRAINT relationships_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: repositories repositories_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.repositories
    ADD CONSTRAINT repositories_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: risk_assessments risk_assessments_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.risk_assessments
    ADD CONSTRAINT risk_assessments_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: risk_assessments risk_assessments_risk_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.risk_assessments
    ADD CONSTRAINT risk_assessments_risk_profile_id_fkey FOREIGN KEY (risk_profile_id) REFERENCES public.risk_profiles(id);


--
-- Name: risk_assessments risk_assessments_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.risk_assessments
    ADD CONSTRAINT risk_assessments_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: risk_assessments risk_assessments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.risk_assessments
    ADD CONSTRAINT risk_assessments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: risk_profiles risk_profiles_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.risk_profiles
    ADD CONSTRAINT risk_profiles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: scans scans_repository_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_repository_id_fkey FOREIGN KEY (repository_id) REFERENCES public.repositories(id) ON DELETE CASCADE;


--
-- Name: scans scans_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: snapshots snapshots_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.snapshots
    ADD CONSTRAINT snapshots_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: snapshots snapshots_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ecdat
--

ALTER TABLE ONLY public.snapshots
    ADD CONSTRAINT snapshots_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict fJgN805giwJxgbfBie5ATfa8e5igAFbJjdQ6ZVBIIePx3KySxvtDIhr0JIbqT0K

