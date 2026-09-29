"""Machine-readable static discovery scope, not runtime assurance."""
CAPABILITIES = {
    'Python AST': 'SUPPORTED: recognized imported API calls; no whole-program dataflow',
    'Java AST': 'SUPPORTED: recognized JCA factories; no whole-program dataflow',
    'Certificates': 'SUPPORTED: X.509 metadata',
    'Containers': 'SUPPORTED: static extraction; never executed',
    'APK': 'STATIC / JADX OPTIONAL',
    'PE/EXE': 'STATIC / GHIDRA OPTIONAL',
    'ELF': 'STATIC / GHIDRA OPTIONAL',
    'JavaScript': 'STRING INDICATORS',
    'Go': 'STRING INDICATORS',
    'Hardware modules': 'NOT YET DISCOVERED',
    'Cloud services': 'NOT YET DISCOVERED',
    'Runtime cryptography': 'OUT OF SCOPE',
}
