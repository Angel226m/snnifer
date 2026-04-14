#!/usr/bin/env python3
"""Generate bcrypt hash for password"""
import sys
sys.path.insert(0, '/app')

from app.crypto import hash_password

password = "angel22"
hashed = hash_password(password, rounds=5)
print(hashed)
