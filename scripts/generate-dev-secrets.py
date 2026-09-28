#!/usr/bin/env python3
import hashlib, secrets
from cryptography.fernet import Fernet
password = input("Demo dashboard password: ")
print("SECRET_KEY=" + secrets.token_urlsafe(48))
print("AUTH_PASSWORD_HASH=" + hashlib.sha256(password.encode()).hexdigest())
print("PROVIDER_ENCRYPTION_KEY=" + Fernet.generate_key().decode())
print("API_KEY=" + secrets.token_urlsafe(32))
