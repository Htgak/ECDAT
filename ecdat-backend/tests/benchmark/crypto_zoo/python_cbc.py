from cryptography.hazmat.primitives.ciphers import algorithms,modes,Cipher
cipher=Cipher(algorithms.AES(key),modes.CBC(iv))
