export type ConfidenceLevel = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFERRED' | 'OBSERVED' | 'INDICATOR';
export type AnalysisStatus = 'DEFINITIVE' | 'AMBIGUOUS' | 'UNRESOLVED';
export type UsageEvidence = 'DIRECT_CALL' | 'CONFIGURATION' | 'IMPORT_ONLY' | 'DEPENDENCY_SPEC' | 'TRANSITIVE_DEPENDENCY';
export type MoscaVerdict = 'act_now' | 'monitor' | 'safe' | 'not_assessed' | 'not_applicable';

export interface Asset {
  id: string;
  tenant_id: string;
  stable_id: string;
  asset_type: 'ALGORITHM' | 'KEY' | 'CERTIFICATE' | 'PROTOCOL' | 'LIBRARY';
  algorithm: string;
  key_size: number | null;
  curve: string | null;
  provider: string | null;
  confidence: ConfidenceLevel;
  analysis_status: AnalysisStatus;
  usage_evidence: UsageEvidence;
  has_conflict: boolean;
  created_at: string;
  // Annotated risk & discovery fields
  qars_score?: number;
  mosca_verdict?: MoscaVerdict;
  repository?: string;
  occurrences_count?: number;
  exposure?: 'EXTERNAL' | 'INTERNAL' | 'ISOLATED';
  criticality?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface Finding {
  occurrence_id: string;
  asset_id: string;
  scan_id: string | null;
  location_type: 'source' | 'dependency' | 'container' | 'binary';
  repository: string | null;
  file_path: string | null;
  line: number | null;
  observation_type: string | null;
  detection_rule_id: string | null;
  detection_rule_version: string | null;
  collector_name: string;
  collector_version: string;
  confidence: ConfidenceLevel;
  created_at: string;
  code_snippet?: string;
  raw_evidence?: Record<string, unknown>;
}

export interface Scan {
  id: string;
  tenant_id: string;
  repository_id: string;
  repository_name: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  commit_ref: string | null;
  started_at: string | null;
  completed_at: string | null;
  is_complete: boolean;
  created_at: string;
  asset_count: number;
  act_now_count: number;
  avg_qars_score: number | null;
}

export interface ScanRiskSummary {
  scan_id: string;
  total_assets: number;
  act_now_count: number;
  monitor_count: number;
  safe_count: number;
  avg_qars_score: number | null;
}

export interface PolicyResult {
  id: string;
  rule_id: string;
  rule_name: string;
  standard: string;
  scan_id?: string; location?: string; engine?: string; policy_version?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  verdict: 'pass' | 'fail' | 'exempt' | 'warn' | 'unknown';
  offending_property: string | null;
  offending_value: string | null;
  explanation: string | null;
  asset_algorithm?: string;
  created_at: string;
}

export interface PQCAdvisory {
  id?: string; scan_id?: string; filename?: string; location?: string; evidence?: string; alternatives?: string[]; recommendation?: string; tradeoffs?: string; references?: string[];
  classical_algorithm: string;
  pqc_replacement: string;
  standard: string;
  transition_tier: 'URGENT' | 'HIGH' | 'MEDIUM' | 'STANDARD' | 'REVIEW';
  target_deadline: string | null;
  estimated_effort_weeks: number | null;
  fips_standard: string | null;
  rationale: string;
}

export interface Snapshot {
  id: string;
  scan_id: string;
  canonical_hash: string;
  merkle_root: string;
  tsa_timestamp_at: string | null;
  is_verified: boolean;
  created_at: string;
}

export interface AuditRecord {
  id: string;
  event_type: string;
  actor: string;
  resource_type: string;
  resource_id: string;
  timestamp: string;
  details: Record<string, unknown>;
}

export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

