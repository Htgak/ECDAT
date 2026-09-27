ALTER TYPE confidence ADD VALUE IF NOT EXISTS 'confirmed';
ALTER TYPE confidence ADD VALUE IF NOT EXISTS 'probable';
ALTER TYPE confidence ADD VALUE IF NOT EXISTS 'unconfirmed';

ALTER TYPE analysisstatus ADD VALUE IF NOT EXISTS 'observed';
ALTER TYPE analysisstatus ADD VALUE IF NOT EXISTS 'not_observed';
ALTER TYPE analysisstatus ADD VALUE IF NOT EXISTS 'unknown';
ALTER TYPE analysisstatus ADD VALUE IF NOT EXISTS 'indeterminate';
ALTER TYPE analysisstatus ADD VALUE IF NOT EXISTS 'unsupported';

ALTER TYPE usageevidence ADD VALUE IF NOT EXISTS 'static';
ALTER TYPE usageevidence ADD VALUE IF NOT EXISTS 'dynamic';
ALTER TYPE usageevidence ADD VALUE IF NOT EXISTS 'inferred';

ALTER TYPE matchtype ADD VALUE IF NOT EXISTS 'stable_external_id';
ALTER TYPE matchtype ADD VALUE IF NOT EXISTS 'certificate_fingerprint';
ALTER TYPE matchtype ADD VALUE IF NOT EXISTS 'package_coordinates';
ALTER TYPE matchtype ADD VALUE IF NOT EXISTS 'repo_path_semantic';
ALTER TYPE matchtype ADD VALUE IF NOT EXISTS 'normalized_observation';
ALTER TYPE matchtype ADD VALUE IF NOT EXISTS 'new_asset';
ALTER TYPE matchtype ADD VALUE IF NOT EXISTS 'possible_duplicate';

ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'algorithm_use';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'key_generation';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'signing';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'verification';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'encryption';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'decryption';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'hashing';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'key_agreement';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'key_derivation';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'random_generation';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'certificate_operation';
ALTER TYPE observationtype ADD VALUE IF NOT EXISTS 'hardcoded_material';

ALTER TYPE policypackstatus ADD VALUE IF NOT EXISTS 'active';
ALTER TYPE policypackstatus ADD VALUE IF NOT EXISTS 'draft';
ALTER TYPE policypackstatus ADD VALUE IF NOT EXISTS 'review';
ALTER TYPE policypackstatus ADD VALUE IF NOT EXISTS 'superseded';
ALTER TYPE policypackstatus ADD VALUE IF NOT EXISTS 'retired';

CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_stable_id ON assets (stable_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_assessments_asset_scan ON risk_assessments (asset_id, scan_id);
