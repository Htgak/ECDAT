export type EvidenceFinding = {
  subject?: string; issuer?: string; serial?: string; valid_from?: string; expires_at?: string; signature_algorithm?: string; fingerprint?: string;
  algorithm?: string; algorithm_raw?: string; operation?: string | null; family?: string;
  padding?: string | null; curve?: string | null; provider?: string | null;
  confidence?: string; scanner?: string; scanner_version?: string; rule_id?: string; rule_version?: string;
  classical_status?: string; quantum_transition_status?: string; policy_status?: string;
  standard_status?: string; runtime_use?: string; limitations?: string[]; references?: string[];
  planning_priority?: {score: number | null; model: string; breakdown: Record<string, number>; meaning: string};
  recommendation_explanation?: {because: string[]; standard_basis: string[]};
};

export function FindingEvidence({finding}: {finding: EvidenceFinding}) {
  return <div className="evidence-first">
    <h3>Why this finding?</h3>
    <dl className="evidence-definition">{Object.entries({
      'Raw observed algorithm': finding.algorithm_raw, Operation: finding.operation,
      Family: finding.family, Padding: finding.padding, Curve: finding.curve, Provider: finding.provider,
      ...(finding.fingerprint ? {Subject: finding.subject, Issuer: finding.issuer, Serial: finding.serial, 'Valid from': finding.valid_from, 'Valid to': finding.expires_at, 'Signature OID': finding.signature_algorithm, 'SHA-256 fingerprint': finding.fingerprint} : {}), Confidence: finding.confidence, 'Scanner / tool': finding.scanner,
      'Scanner version': finding.scanner_version, 'Rule ID': finding.rule_id,
      'Rule version': finding.rule_version, 'Runtime use': finding.runtime_use ?? 'NOT CONFIRMED',
    }).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value || 'Unknown / not observed'}</dd></div>)}</dl>
    <h3>Security and transition status</h3>
    <dl className="evidence-definition">{Object.entries({
      Classical: finding.classical_status, Quantum: finding.quantum_transition_status?.replaceAll('_', ' '),
      'Organization policy': finding.policy_status, 'Standard maturity': finding.standard_status,
    }).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value || 'Not assessed'}</dd></div>)}</dl>
    {finding.planning_priority && <><h3>{finding.planning_priority.model}</h3>
      <p>{finding.planning_priority.meaning}</p>
      {finding.planning_priority.score == null ? <p>Not assessed — supply the required organizational context.</p> : <>
        <p>Score = rounded sum of the contributions below.</p>
        <dl className="evidence-definition">{Object.entries(finding.planning_priority.breakdown).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl>
      </>}</>}
    {finding.recommendation_explanation && <><h3>Why this recommendation?</h3><ul>{finding.recommendation_explanation.because.map(reason => <li key={reason}>{reason}</li>)}</ul></>}
    {!!finding.references?.length && <><h3>Standards references</h3><ul>{finding.references.filter(url => url.startsWith('https://')).map(url => <li key={url}><a href={url} target="_blank" rel="noreferrer">{url}</a></li>)}</ul></>}
    {!!finding.limitations?.length && <><h3>Limitations</h3>{finding.limitations.map(note => <p key={note}>{note}</p>)}</>}
  </div>;
}
