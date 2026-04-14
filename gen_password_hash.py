#!/usr/bin/env python3
import bcrypt

# Generar hash real con bcrypt rounds=5 igual que el backend
password = "angel22"
rounds = 5

salt = bcrypt.gensalt(rounds=rounds)
password_hash = bcrypt.hashpw(password.encode(), salt)
hash_string = password_hash.decode()

print(f"Contraseña: {password}")
print(f"Rounds: {rounds}")
print(f"Hash: {hash_string}")
print()
print("Para init-db.sql, usa:")
print(f"    '{hash_string}',")
