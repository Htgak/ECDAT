"""Offline official-schema validation; no remote reference retrieval."""
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource

SCHEMAS = Path(__file__).parent / 'schemas'


@lru_cache(maxsize=3)
def validator(name: str):
    registry = Registry()
    for path in SCHEMAS.glob('*.json'):
        schema = json.loads(path.read_text(encoding='utf-8'))
        resource = Resource.from_contents(schema)
        for uri in [schema.get('$id', path.as_uri()), 'http://cyclonedx.org/schema/' + path.name,
                    'https://cyclonedx.org/schema/' + path.name, path.as_uri()]:
            registry = registry.with_resource(uri, resource)
    schema = json.loads((SCHEMAS / name).read_text(encoding='utf-8'))
    return Draft7Validator(schema, registry=registry, format_checker=FormatChecker())


def validate_document(document: dict, name: str) -> None:
    validator(name).validate(document)


def cbom17(record: dict, stable: dict) -> dict:
    from copy import deepcopy
    document = deepcopy(stable)
    document['specVersion'] = '1.7'
    families = json.loads((SCHEMAS / 'cryptography-defs.schema.json').read_text())['definitions']['algorithmFamiliesEnum']['enum']
    for component, finding in zip(document['components'], record['findings']):
        crypto = component.get('cryptoProperties')
        if not crypto or crypto['assetType'] != 'algorithm':
            continue
        alg, operation = finding['algorithm'], finding.get('operation')
        props = {}
        if alg in families:
            props['algorithmFamily'] = alg
        primitive = ('signature' if operation in {'sign', 'verify'} else 'kem' if alg == 'ML-KEM' else
                     'signature' if alg in {'ML-DSA', 'SLH-DSA', 'ECDSA', 'Ed25519', 'Ed448', 'DSA'} else
                     'key-agree' if alg in {'ECDH', 'DH', 'X25519', 'X448'} else
                     'ae' if alg == 'AES' and finding.get('mode') in {'GCM', 'CCM'} else
                     'block-cipher' if alg in {'AES', 'DES', '3DES'} else
                     'hash' if finding.get('family') == 'hash' else
                     'mac' if finding.get('family') == 'mac' else
                     'kdf' if finding.get('family') == 'kdf' else
                     'pke' if alg == 'RSA' and operation in {'encrypt', 'decrypt'} else None)
        if primitive:
            props['primitive'] = primitive
        if operation in {'generate', 'keygen', 'encrypt', 'decrypt', 'digest', 'tag', 'keyderive', 'sign', 'verify', 'encapsulate', 'decapsulate'}:
            props['cryptoFunctions'] = [operation]
        if alg in {'AES', 'DES', '3DES'} and (finding.get('mode') or '').lower() in {'cbc', 'ecb', 'ccm', 'gcm', 'cfb', 'ofb', 'ctr'}:
            props['mode'] = finding['mode'].lower()
        padding = {'PKCS5Padding': 'pkcs5', 'PKCS7Padding': 'pkcs7', 'PKCS1Padding': 'pkcs1v15', 'NoPadding': 'raw'}.get(finding.get('padding'))
        if padding:
            props['padding'] = padding
        if finding.get('key_size'):
            props['parameterSetIdentifier'] = str(finding['key_size'])
        if finding.get('parameter_set'):
            props['parameterSetIdentifier'] = finding['parameter_set']
        quantum_level = {('ML-KEM', '512'): 1, ('ML-KEM', '768'): 3, ('ML-KEM', '1024'): 5,
                         ('ML-DSA', '44'): 2, ('ML-DSA', '65'): 3, ('ML-DSA', '87'): 5}.get((alg, finding.get('parameter_set')))
        if quantum_level:
            props['nistQuantumSecurityLevel'] = quantum_level
        if alg == 'AES' and finding.get('key_size') in {128, 192, 256}:
            props['classicalSecurityLevel'] = finding['key_size']
        if props:
            crypto['algorithmProperties'] = props
    validate_document(document, 'bom-1.7.schema.json')
    return document
