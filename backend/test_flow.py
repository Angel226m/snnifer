#!/usr/bin/env python3
"""
Demonstration of the full communication flow between frontend and backend.
Shows what gets encrypted/hashed, what stays in plaintext, and where.
"""

import json
import bcrypt
from datetime import datetime, timedelta
from jose import jwt
import os

# ============= CONFIGURATION =============
SECRET_KEY = "test-secret-key-12345"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

print("=" * 80)
print("FRONTEND ↔ BACKEND COMMUNICATION FLOW")
print("=" * 80)

# ============= STEP 1: USER REGISTRATION =============
print("\n1️⃣  FRONTEND: User submits registration form")
print("-" * 80)

frontend_registration_payload = {
    "email": "angel@gmail.com",
    "password": "angel22"  # PLAINTEXT in memory
}

print(f"Frontend memory (user input):")
print(f"  email: {frontend_registration_payload['email']}")
print(f"  password: {frontend_registration_payload['password']}")

print(f"\n→ Frontend sends over HTTPS (encrypted by TLS/SSL):")
print(f"  POST /auth/register")
print(f"  Body (plaintext inside HTTPS tunnel):")
print(f"  {json.dumps(frontend_registration_payload, indent=4)}")

# ============= STEP 2: BACKEND RECEIVES & PROCESSES =============
print("\n\n2️⃣  BACKEND: Receives registration")
print("-" * 80)

email = frontend_registration_payload["email"]
password = frontend_registration_payload["password"]

print(f"Backend receives (inside secure HTTPS tunnel):")
print(f"  email: {email}")
print(f"  password: {password} (plaintext, not readable by attacker if using HTTPS)")

# Hash password with bcrypt
salt = bcrypt.gensalt(rounds=5)
password_hash = bcrypt.hashpw(password.encode(), salt).decode()

print(f"\n✓ Backend hashes password with bcrypt (5 rounds):")
print(f"  Original: {password}")
print(f"  Hashed:   {password_hash}")
print(f"  Status: IRREVERSIBLE - cannot get back original password")

# ============= STEP 3: DATABASE STORAGE =============
print("\n\n3️⃣  DATABASE: What gets stored")
print("-" * 80)

db_user_record = {
    "id": 1,
    "email": email,  # Plaintext in database
    "password_hash": password_hash,  # Hashed, not reversible
    "created_at": datetime.utcnow().isoformat()
}

print(f"Stored in PostgreSQL 'users' table:")
for field, value in db_user_record.items():
    print(f"  {field}: {value}")

print(f"\n🔐 Security status:")
print(f"  - email: PLAINTEXT (needed to find user on login)")
print(f"  - password_hash: HASHED (password cannot be recovered)")

# ============= STEP 4: JWT TOKEN GENERATION =============
print("\n\n4️⃣  BACKEND: Generate JWT token")
print("-" * 80)

payload = {
    "sub": str(db_user_record["id"]),
    "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
}

access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

print(f"Access token (signed & timestamped):")
print(f"  {access_token}")
print(f"\n📋 Token contains:")
print(f"  - sub (user ID): {payload['sub']}")
print(f"  - exp (expiration): {payload['exp']}")
print(f"  - Signature: (verified with SECRET_KEY)")

# ============= STEP 5: RESPONSE TO FRONTEND =============
print("\n\n5️⃣  BACKEND → FRONTEND: Response")
print("-" * 80)

response_payload = {
    "message": "Registration successful",
    "access_token": access_token,
    "token_type": "bearer",
    "user": {
        "id": db_user_record["id"],
        "email": db_user_record["email"],
        "created_at": db_user_record["created_at"]
    }
}

print(f"Backend sends over HTTPS:")
print(f"  {json.dumps(response_payload, indent=4)}")
print(f"\n⚠️  Password is NOT in response (good security!)")

# ============= STEP 6: FRONTEND STORES TOKEN =============
print("\n\n6️⃣  FRONTEND: Stores JWT in localStorage")
print("-" * 80)

print(f"Frontend localStorage after login:")
print(f"  jwt_token: {access_token}")
print(f"  user: {json.dumps(response_payload['user'])}")
print(f"\n⚠️  Password never stored in frontend (only JWT token)")

# ============= STEP 7: CREATE CLIENT =============
print("\n\n7️⃣  FRONTEND: Create a new client")
print("-" * 80)

client_payload = {
    "name": "Juan",
    "surname": "García",
    "age": 28,
    "dni": "12345678",
    "phone": "612345678",
    "email": "juan.garcia@mail.com",
    "address": "Calle Mayor 1, Madrid"
}

print(f"Frontend sends client data + JWT token:")
print(f"  POST /clients")
print(f"  Headers:")
print(f"    Authorization: Bearer {access_token[:20]}...{access_token[-20:]}")
print(f"    Content-Type: application/json")
print(f"  Body:")
print(f"  {json.dumps(client_payload, indent=4)}")

print(f"\n🔒 Transport security: HTTPS encrypts everything")
print(f"   (JWT, client data, all plaintext inside TLS tunnel)")

# ============= STEP 8: BACKEND VALIDATES JWT & STORES CLIENT =============
print("\n\n8️⃣  BACKEND: Validate token & store client")
print("-" * 80)

try:
    decoded = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id = int(decoded["sub"])
    print(f"✓ JWT valid! Extracted user_id: {user_id}")
except:
    print(f"✗ JWT invalid!")
    user_id = None

if user_id:
    db_client_record = {
        "id": 1,
        "user_id": user_id,
        **client_payload,
        "encrypted": False,  # NOT app-encrypted
        "created_at": datetime.utcnow().isoformat()
    }
    
    print(f"\nStored in PostgreSQL 'clients' table:")
    for field, value in db_client_record.items():
        print(f"  {field}: {value}")
    
    print(f"\n🔒 Storage security:")
    print(f"  - All fields PLAINTEXT in database")
    print(f"  - NOT encrypted at application level")
    print(f"  - Protected by: database access control + HTTPS in transit")

# ============= STEP 9: RESPONSE =============
print("\n\n9️⃣  BACKEND → FRONTEND: Client created")
print("-" * 80)

response_client = {
    "id": db_client_record["id"],
    "user_id": db_client_record["user_id"],
    **{k: v for k, v in db_client_record.items() if k not in ["id", "user_id"]},
}

print(f"Response over HTTPS:")
print(f"  {json.dumps(response_client, indent=4)}")

# ============= SUMMARY =============
print("\n\n" + "=" * 80)
print("SUMMARY: WHERE IS THE DATA ENCRYPTED?")
print("=" * 80)

print(f"""
┌─────────────────────────────────────────────────────────────────┐
│ DATA PROTECTION LAYERS                                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ 1. PASSWORD (User Registration)                                │
│    ├─ Frontend → Backend: PLAINTEXT over HTTPS (TLS encrypted) │
│    ├─ Backend Processing: HASHED with bcrypt (5 rounds)       │
│    └─ Database: HASHED (irreversible)                         │
│                                                                 │
│ 2. JWT TOKEN (Authentication)                                  │
│    ├─ Backend → Frontend: PLAINTEXT over HTTPS                │
│    ├─ Frontend Storage: PLAINTEXT in localStorage              │
│    └─ Sent with requests: Bearer token in Authorization header│
│                                                                 │
│ 3. CLIENT DATA (Name, DNI, Email, etc.)                       │
│    ├─ Frontend → Backend: PLAINTEXT over HTTPS (TLS encrypted)│
│    ├─ Backend Processing: NO APP-LEVEL ENCRYPTION             │
│    └─ Database: PLAINTEXT                                      │
│                                                                 │
│ 4. TRANSPORT SECURITY (ALL requests/responses)                │
│    ├─ HTTPS = TLS/SSL encryption                              │
│    ├─ Protects: passwords, tokens, client data                │
│    └─ Attacker on network cannot see plaintext                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

⚠️  IMPORTANT:
  • No app-level encryption of client data (NOT encrypted)
  • Only password is hashed (one-way, cannot decrypt)
  • All sensitive data must be sent over HTTPS (TLS tunnel)
  • JWT tokens never expire during session persistence
  • Database only protected by access control (no column encryption)

✓ WHAT'S CORRECT:
  • Password hashing with bcrypt
  • HTTPS for transport security
  • JWT for stateless authentication
  • No password storage in frontend

❌ WHAT'S MISSING (if needed):
  • Column-level database encryption
  • TDE (Transparent Data Encryption) at database level
  • Encryption at rest for sensitive fields
""")

print("\n" + "=" * 80)
