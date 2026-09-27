-- PostgreSQL initialization for ECDAT
-- Runs once when the container starts for the first time.

-- Enable pgcrypto for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Enable pg_trgm for fuzzy text search on algorithm names
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Create a dedicated keycloak database if auth profile is active
-- (this is handled by Keycloak's own init, but we create the DB here)
SELECT 'Database initialized.' AS status;
