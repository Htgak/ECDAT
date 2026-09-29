from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
k=PBKDF2HMAC(algorithm=algo,length=32,salt=salt,iterations=600000)
