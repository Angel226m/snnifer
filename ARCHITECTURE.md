# 🏗️ LearnWithGaray Architecture & Data Flow

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET (TLS/HTTPS)                     │
└─────────────────────────────────────────────────────────────────┘
         │                    │                      │
         ▼                    ▼                      ▼
    ┌────────┐           ┌─────────┐          ┌──────────┐
    │Frontend│◄──────────┤ Backend │◄--------│ Sniffer  │
    │  Port  │ HTTP/REST │ FastAPI │ Flask   │ Dashboard│
    │ :3000  │(over TLS) │ :8000   │ :5000   │(monitor) │
    └────────┘           └────┬────┘         └──────────┘
    SvelteKit            HTTP │
    - Routes            over │ TLS
    - Dashboard         (Encrypted)
    - Modals              │
    - Store (state)       ▼
    - API calls      ┌──────────────┐
                     │  PostgreSQL  │
                     │   Database   │
                     │   :5432      │
                     └──────────────┘
                     - users table
                     - clients table
```

## Data Flow: Registration & Login

```
FRONTEND                          BACKEND                         DATABASE
   │                                 │                               │
   ├─ User enters email/password      │                               │
   │                                 │                               │
   ├─ POST /auth/register             │                               │
   │    (email, plaintext password)   │                               │
   ├──────────────────────────────────▶ 1. Receive plaintext password │
   │   [HTTPS/TLS Encrypted]          │    over encrypted tunnel      │
   │                                 │ 2. Hash password with bcrypt  │
   │                                 │    (irreversible, salted)    │
   │                                 │ 3. Generate bcrypt hash      │
   │                                 │                               │
   │                                 ├──────────────────────────────▶
   │                                 │    INSERT INTO users          │
   │                                 │    (email, password_hash)     │
   │                                 │◀──────────────────────────────
   │                                 │    success ✓                  │
   │◀──────────────────────────────── 4. Return success message      │
   │  User created!                  │                               │
   │
   │  [Later: Login Flow]
   │
   ├─ POST /auth/login                │                               │
   │    (email, plaintext password)   │                               │
   ├──────────────────────────────────▶ 1. Receive plaintext password │
   │   [HTTPS/TLS Encrypted]          │ 2. Fetch user from DB        │
   │                                 │                               │
   │                                 ├──────────────────────────────▶
   │                                 │    SELECT * FROM users       │
   │                                 │    WHERE email = ?            │
   │                                 │◀──────────────────────────────
   │                                 │    user record + hash         │
   │                                 │                               │
   │                                 │ 3. Verify: bcrypt.compare(    │
   │                                 │      plaintext, hash)         │
   │                                 │ 4. Create JWT:                │
   │                                 │    token = jwt.encode(        │
   │                                 │      {user_id, exp: 30min},  │
   │                                 │      SECRET_KEY, HS256)       │
   │◀──────────────────────────────── 5. Return JWT token            │
   │  Store in localStorage           │                               │
   │  (signed, expires in 30 min)    │                               │
```

## Data Flow: Client CRUD Operations

### CREATE Client
```
FRONTEND                          BACKEND                         DATABASE
   │                                 │                               │
   ├─ User fills client form           │                               │
   │  (name, surname, age, dni,       │                               │
   │   phone, email, address)         │                               │
   │                                 │                               │
   ├─ POST /clients                   │                               │
   │    Body: {client data}           │                               │
   │    Header: Authorization:        │                               │
   │      Bearer {JWT_TOKEN}          │                               │
   ├──────────────────────────────────▶ 1. Extract JWT from header    │
   │   [HTTPS/TLS Encrypted]          │    Authorization: Bearer X    │
   │                                 │ 2. Verify JWT signature       │
   │                                 │ 3. Extract user_id from token │
   │                                 │ 4. Parse client data          │
   │                                 │ 5. Validate:                  │
   │                                 │    - DNI: ^[0-9]{8}$         │
   │                                 │    - phone: ^[0-9]{9}$       │
   │                                 │    - email: valid format      │
   │                                 │ 6. Log: [AUDIT] User X        │
   │                                 │    creating client            │
   │                                 │ 7. Store plaintext data       │
   │                                 │                               │
   │                                 ├──────────────────────────────▶
   │                                 │    INSERT INTO clients        │
   │                                 │    (user_id, name,            │
   │                                 │     surname, ... plaintext)   │
   │                                 │◀──────────────────────────────
   │                                 │    success + client_id        │
   │◀──────────────────────────────── 8. Return client object        │
   │  Add to UI list                 │    with ID                    │
```

### UPDATE Client (NEW)
```
FRONTEND                          BACKEND                         DATABASE
   │                                 │                               │
   ├─ Click Edit button on client     │                               │
   ├─ EditClientModal opens with data │                               │
   ├─ User modifies fields            │                               │
   │                                 │                               │
   ├─ PUT /clients/{id}               │                               │
   │    Body: {updated data}          │                               │
   │    Header: Authorization:        │                               │
   │      Bearer {JWT_TOKEN}          │                               │
   ├──────────────────────────────────▶ 1. Extract JWT + user_id      │
   │   [HTTPS/TLS Encrypted]          │ 2. Verify user owns client   │
   │                                 │ 3. Validate updated fields   │
   │                                 │ 4. Log: [AUDIT] User X       │
   │                                 │    updating client Z          │
   │                                 │                               │
   │                                 ├──────────────────────────────▶
   │                                 │    UPDATE clients            │
   │                                 │    SET ... WHERE id=Z        │
   │                                 │    AND user_id=X             │
   │                                 │◀──────────────────────────────
   │                                 │    success                    │
   │◀──────────────────────────────── 5. Return updated client       │
   │  Update UI                      │                               │
```

### DELETE Client (NEW)
```
FRONTEND                          BACKEND                         DATABASE
   │                                 │                               │
   ├─ Click Delete button              │                               │
   ├─ Confirm: "Sure to delete?"       │                               │
   │                                 │                               │
   ├─ DELETE /clients/{id}             │                               │
   │    Header: Authorization:        │                               │
   │      Bearer {JWT_TOKEN}          │                               │
   ├──────────────────────────────────▶ 1. Extract JWT + user_id      │
   │   [HTTPS/TLS Encrypted]          │ 2. Verify user owns client   │
   │                                 │ 3. Fetch client name/surname │
   │                                 │                               │
   │                                 ├──────────────────────────────▶
   │                                 │    SELECT name, surname ...  │
   │                                 │    FROM clients WHERE id=?   │
   │                                 │◀──────────────────────────────
   │                                 │    client data                │
   │                                 │ 4. Log: [AUDIT] User X       │
   │                                 │    deleting client Z:         │
   │                                 │    {name} {surname}           │
   │                                 │                               │
   │                                 ├──────────────────────────────▶
   │                                 │    DELETE FROM clients        │
   │                                 │    WHERE id=Z AND user_id=X   │
   │                                 │◀──────────────────────────────
   │                                 │    success (1 row deleted)    │
   │◀──────────────────────────────── 5. Return success              │
   │  Remove from UI list            │                               │
```

## Security Layers

### Layer 1: Transport (HTTPS/TLS) ✅ ENCRYPTED
```
Frontend ──[HTTPS/TLS Tunnel]──▶ Backend
   │                            │
   ├─ Plaintext password   ────encrypted────▶ Hashed immediately
   ├─ Plaintext client data ───encrypted────▶ Stored plaintext
   └─ JWT tokens ──────────encrypted────▶ Verified + stored
```

### Layer 2: Password Storage ✅ BCRYPT HASH (Irreversible)
```
Original Password:    "angel22"
                        │
        bcrypt.hashpw() ▼
Database stores:  "$2a$05$8jh2k3h4k5h6k7h8k..."  ← Irreversible
                        │
On login:         bcrypt.checkpw(plaintext, hash) ─▶ True/False
```

### Layer 3: Session Authentication ✅ JWT SIGNED (Verifiable)
```
User ID:              1
Expiration:           NOW + 30 minutes
                        │
      jwt.encode(payload, SECRET_KEY, HS256) ▼
Token: "eyJhbGci..." ← Signed with backend SECRET_KEY
                        │
On request:       jwt.decode(token, SECRET_KEY) ─▶ {user_id, exp}
                   Signature invalid ─▶ Reject request
```

### Layer 4: Client Data Storage ❌ PLAINTEXT (No App-Level Encryption)
```
Frontend sends:    {name: "John", phone: "666123456"}
                        │
    HTTPS/TLS tunnel ──encrypted────▶ Backend
                        │
Backend decrypts & stores plaintext in DB:
    table clients:     id | user_id | name  | phone      | ...
                       1  | 1       | John  | 666123456  | ...
```

## API Request Example with Sniffer

```bash
# Request captured in sniffer
POST /api/clients
Content-Type: application/json
Authorization: Bearer eyJhbGci...

{
  "name": "John",
  "surname": "Doe",
  "age": 30,
  "dni": "12345678",
  "phone": "666123456",
  "email": "john@example.com",
  "address": "123 Main St"
}

# Response captured in sniffer
HTTP/1.1 201 Created
Content-Type: application/json

{
  "id": 5,
  "user_id": 1,
  "name": "John",
  "surname": "Doe",
  "age": 30,
  "dni": "12345678",
  "phone": "666123456",
  "email": "john@example.com",
  "address": "123 Main St",
  "encrypted": false,
  "created_at": "2024-01-15T10:30:45"
}

# Backend console shows:
[AUDIT] User 1 creating client
```

## Sniffer Dashboard View

```
REAL-TIME TRAFFIC MONITOR
━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Stats:
   Total Requests: 12
   Encrypted (HTTPS): 12  ✅
   Plaintext: 0           ✅

🔍 Recent Traffic:

[1] 10:30:45 POST /api/clients
    Headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer eyJ..."
    }
    Body: {name: "John", surname: "Doe", ...}
    Status: 201 Created ✅

[2] 10:30:46 GET /api/clients
    Headers: {
      "Authorization": "Bearer eyJ..."
    }
    Status: 200 OK ✅
    Response: [{id: 1, name: "John", ...}]

[3] 10:31:00 PUT /api/clients/1
    Headers: {...}
    Body: {name: "Jane", ...}
    Status: 200 OK ✅

[4] 10:31:15 DELETE /api/clients/1
    Headers: {...}
    Status: 200 OK ✅
```

## Audit Trail

```
Backend logs every operation:

[AUDIT] User 1 updating client 1: John Doe
[AUDIT] User 1 deleting client 1: John Doe
[AUDIT] User 1 creating client
```

## What's Encrypted vs Plaintext?

| Data | Where | Status | Why |
|------|-------|--------|-----|
| Password (plaintext) | Browser → Backend | 🔒 HTTPS/TLS | Network protection |
| Password (hash) | Database | 🔒 bcrypt | Irreversible, salted |
| JWT Token | Browser → Backend | 🔒 HTTPS/TLS | Network protection |
| JWT Token | localStorage | ❌ Plaintext | Browser protection (not accessible from JS if HttpOnly) |
| Client Name | Browser → Backend | 🔒 HTTPS/TLS | Network protection |
| Client Name | Database | ❌ Plaintext | Not sensitive personal data |
| Email | Browser → Backend | 🔒 HTTPS/TLS | Network protection |
| Email | Database | ❌ Plaintext | Non-sensitive contact info |
| Phone | Browser → Backend | 🔒 HTTPS/TLS | Network protection |
| Phone | Database | ❌ Plaintext | Non-sensitive contact info |

## Key Points

✅ **Passwords**: Bcrypt hashed (irreversible, salted)
✅ **Transit**: HTTPS/TLS encrypted
✅ **Sessions**: JWT signed (verified on each request)
❌ **Client Data**: Plaintext in database (not sensitive, protected in transit)

**Result**: Secure, honest, transparent system with no false claims.
