"""Measure labelled input through the SAME perform_scan used by uploads.

Run: python benchmarks/run_full_benchmark.py
Matching unit: (case file, canonical algorithm). Repeated observations of the
same algorithm in a case count once. Negative cases contribute false positives.
This measures discovery, not runtime use or compliance. No accuracy targets.
"""
import hashlib
import json
import sys
import tempfile
import uuid
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ecdat.apps.api.routers.uploads import perform_scan, now


def run():
    corpus = ROOT / 'tests/benchmark/crypto_zoo'
    cases = json.loads((corpus / 'manifest.json').read_text())['cases']
    totals, groups, details = Counter(), defaultdict(Counter), []
    with tempfile.TemporaryDirectory(prefix='ecdat-benchmark-') as temp:
        for case in cases:
            folder = Path(temp) / str(uuid.uuid4())
            folder.mkdir(mode=0o700)
            path = corpus / case['file']
            kind = case.get('kind', 'source')
            # Metadata artefacts are carried in a source ZIP, as in the UI.
            if case['category'] == 'Certificate':
                filename = path.stem + '.zip'
                with zipfile.ZipFile(folder / 'original', 'w') as archive:
                    archive.write(path, path.name)
            else:
                filename = path.name
                (folder / 'original').write_bytes(path.read_bytes())
            record = dict(id=folder.name, filename=filename, kind=kind, context={}, created_at=now(),
                          sha256=hashlib.sha256((folder / 'original').read_bytes()).hexdigest())
            perform_scan(folder, record)
            expected = set(case['expected'])
            actual = {f['algorithm'] for f in record['findings']}
            counts = Counter(tp=len(expected & actual), fp=len(actual - expected), fn=len(expected - actual))
            totals.update(counts)
            groups[case['category']].update(counts)
            details.append(dict(file=case['file'], expected=sorted(expected), actual=sorted(actual), **counts))
    def metrics(counts):
        tp, fp, fn = counts['tp'], counts['fp'], counts['fn']
        p = tp / (tp + fp) if tp + fp else 0
        r = tp / (tp + fn) if tp + fn else 0
        return dict(counts, precision=p, recall=r, f1=2*p*r/(p+r) if p+r else 0)
    result = dict(cases=len(cases), ground_truth=sum(len(c['expected']) for c in cases),
                  negative_controls=sum(not c['expected'] for c in cases), metrics=metrics(totals),
                  categories={key: metrics(value) for key, value in groups.items()}, details=details,
                  matching='case file + canonical algorithm; repeated observations collapse within a case',
                  limitation='Synthetic discovery benchmark; not evidence of exhaustive production accuracy.')
    output = ROOT / 'benchmarks/results'
    output.mkdir(exist_ok=True)
    (output / 'crypto-zoo.json').write_text(json.dumps(result, indent=2))
    print('ECDAT Discovery Benchmark\n')
    print(f"Labelled cases: {len(cases)}; negative controls: {result['negative_controls']}")
    print(f"Ground truth artefacts: {result['ground_truth']}")
    print(f"Detected correctly: {totals['tp']}\nFalse positives: {totals['fp']}\nMissed: {totals['fn']}")
    for name in ['precision', 'recall', 'f1']:
        print(f"{name.title()}: {result['metrics'][name]:.1%}")
    for name, value in result['categories'].items():
        print(f"{name}: TP={value['tp']} FP={value['fp']} FN={value['fn']}; F1={value['f1']:.1%}")
    return result


if __name__ == '__main__':
    run()
