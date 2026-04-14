# Login & Client Management Application

A full-stack application with bcrypt-hashed authentication and client management built with Svelte, FastAPI, and PostgreSQL.

## Features

- **Secure Authentication**: Email/password login with bcrypt (5 rounds) hashing
- **Client Management**: Add, view, edit, and delete clients
- **JWT Tokens**: Stateless authentication with JWT
- **Docker Support**: Multistage builds for optimized container images

## Tech Stack

- **Frontend**: SvelteKit + Tailwind CSS
- **Backend**: FastAPI + SQLAlchemy
- **Database**: PostgreSQL
- **Containerization**: Docker & Docker Compose

## Prerequisites

- Docker & Docker Compose
- Or: Node.js 18+, Python 3.11+, PostgreSQL 15+

## Quick Start with Docker

### 1. Clone and Setup

```bash
# Copy environment file
cp .env.example .env

# Copy backend env
cp backend/.env.example backend/.env

# Copy frontend env
cp frontend/.env.example frontend/.env
```

### 2. Start Services

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### 3. Access Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Database**: localhost:5432

## Demo Credentials

```
Email: demo@example.com
Password: password123
```

## Local Development

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Set DATABASE_URL
export DATABASE_URL=postgresql://user:password@localhost:5432/login_db

# Run migrations (tables are created automatically)
python -m app.main

# Run server
uvicorn app.main:app --reload
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Create .env file
cp .env.example .env

# Start dev server
npm run dev
```

## API Documentation

### Authentication Endpoints

- `POST /auth/register` - Register new user
- `POST /auth/login` - Login user
- `GET /auth/me` - Get current user

### Client Endpoints

- `GET /clients` - List all clients
- `POST /clients` - Create new client
- `GET /clients/{client_id}` - Get specific client
- `PUT /clients/{client_id}` - Update client
- `DELETE /clients/{client_id}` - Delete client

### Headers

- `Authorization: Bearer {token}` - JWT token required for protected routes

## Data Validation

- **DNI**: Exactly 8 digits
- **Phone**: Exactly 9 digits
- **Email**: Valid email format
- **Password**: Minimum 6 characters

## Password Storage

- Passwords are stored as bcrypt hashes with 5 rounds.
- Client payloads are not app-encrypted; protect the API with HTTPS in deployment.
- JWT is used for session authentication.

## Project Structure

```
.
├── backend/
│   ├── app/
│   │   ├── routes/
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── crypto.py
│   │   ├── crud.py
│   │   ├── database.py
│   │   └── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── routes/
│   │   ├── lib/
│   │   └── styles/
│   ├── package.json
│   └── Dockerfile
└── docker-compose.yml
```

## Troubleshooting

### Port Already in Use

```bash
# Specify different ports in docker-compose.yml or .env
# Or kill existing processes:
lsof -i :3000  # Frontend
lsof -i :8000  # Backend
lsof -i :5432  # Database
```

### Database Connection Error

```bash
# Verify PostgreSQL is running
docker ps | grep postgres

# Check logs
docker-compose logs db
```

### Frontend Can't Connect to Backend

```bash
# Verify CORS_ORIGINS in .env
# Ensure backend is running
docker-compose logs backend

# Test API
curl http://localhost:8000/health
```

## License

MIT
