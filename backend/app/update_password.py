#!/usr/bin/env python3
"""Update password with real bcrypt hash"""
from app.database import SessionLocal
from app import models
from app.crypto import hash_password

db = SessionLocal()
try:
    user = db.query(models.User).filter_by(email="angel@gmail.com").first()
    if user:
        new_hash = hash_password("angel22", rounds=5)
        user.password_hash = new_hash
        db.commit()
        print(f"✅ Contraseña actualizada para {user.email}")
        print(f"Hash: {new_hash}")
    else:
        print("❌ Usuario no encontrado")
finally:
    db.close()
