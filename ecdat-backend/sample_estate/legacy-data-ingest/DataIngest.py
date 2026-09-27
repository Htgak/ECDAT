"""Legacy Data Ingestion Service.
Maintains legacy ETL pipelines using deprecated MD5 hashing and DES.
"""

from typing import Any
import hashlib
from Crypto.Cipher import DES  # type: ignore[import-untyped, import-not-found]  # pyright: ignore[reportMissingImports]

def ingest_legacy_batch(raw_bytes: bytes) -> tuple[str, Any]:
    # Insecure MD5 message digest
    batch_md5 = hashlib.md5(raw_bytes).hexdigest()
    
    # 56-bit DES block cipher
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)
    return batch_md5, cipher
