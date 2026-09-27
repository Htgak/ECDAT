"""Bounded artifact metadata discovery. Never return private key material."""
import json
import re
from pathlib import PurePosixPath

CRYPTO_PACKAGES = {'cryptography', 'pycryptodome', 'pyopenssl', 'openssl', 'crypto-js', 'node-forge', 'bcrypt', 'libsodium', 'bouncycastle', 'bcprov-jdk18on'}
METADATA_EXTENSIONS = {'.pem', '.crt', '.cer', '.der', '.key', '.json', '.txt', '.xml', '.toml', '.lock', '.so', '.dll', '.dylib', '.a', '.jar', '.class'}

def discover(data: bytes, location: str) -> list[dict]:
    findings = []
    def add(algorithm, asset_type, evidence, **values):
        findings.append(dict(algorithm=algorithm, asset_type=asset_type, evidence=evidence,
                             location=location, line=None, priority='info', recommendation='Review actual usage and configuration.', **values))
    text = data.decode('utf-8', errors='replace')
    if PurePosixPath(location).name == 'package.json':
        try:
            manifest = json.loads(text)
            for section in ['dependencies', 'devDependencies', 'optionalDependencies']:
                for name, version in manifest.get(section, {}).items():
                    if name.lower() in CRYPTO_PACKAGES:
                        add('Unknown', 'library', 'Dependency declaration (capability, not usage)', name=name, version=str(version))
        except (ValueError, AttributeError):
            pass
    for name, version in re.findall(r'(?im)^\s*([\w-]+)\s*==\s*([\w.+-]+)', text):
        if name.lower() in CRYPTO_PACKAGES:
            add('Unknown', 'library', 'Pinned dependency declaration', name=name, version=version)
    for version in re.findall(r'OpenSSL[ /](\d+\.\d+\.\d+[a-z]?)', text):
        add('Unknown', 'library', 'Library version string (confirm runtime linkage)', name='OpenSSL', version=version)
    for version in sorted(set(re.findall(r'\bTLSv?(1\.[0-3])\b', text))):
        add('TLS', 'protocol', 'Protocol version indicator', version=version)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, x25519, x448
    def key_info(key):
        mapping = [(rsa.RSAPublicKey, 'RSA'), (ec.EllipticCurvePublicKey, 'EC'), (dsa.DSAPublicKey, 'DSA'), (ed25519.Ed25519PublicKey, 'Ed25519'), (ed448.Ed448PublicKey, 'Ed448'), (x25519.X25519PublicKey, 'X25519'), (x448.X448PublicKey, 'X448')]
        return next((name for cls, name in mapping if isinstance(key, cls)), 'Unknown'), getattr(key, 'key_size', None)
    certs = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', data, re.S)
    if not certs and PurePosixPath(location).suffix.lower() in {'.der', '.cer', '.crt'}:
        certs = [data]
    for raw in certs:
        try:
            cert = x509.load_pem_x509_certificate(raw) if raw.startswith(b'-----') else x509.load_der_x509_certificate(raw)
            algorithm, size = key_info(cert.public_key())
            add(algorithm, 'certificate', 'Parsed X.509 certificate', key_size=size, version=cert.version.name,
                fingerprint=cert.fingerprint(hashes.SHA256()).hex(), expires_at=cert.not_valid_after_utc.isoformat())
        except ValueError:
            pass
    for raw in re.findall(rb'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----', data, re.S):
        try:
            key = serialization.load_pem_private_key(raw, password=None).public_key()
            algorithm, size = key_info(key)
            add(algorithm, 'key', 'Parsed private key; material omitted', key_size=size)
        except (ValueError, TypeError):
            add('Unknown', 'key', 'Private key marker; encrypted or unsupported material')
    return findings
