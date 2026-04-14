from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

from app.database import Base, engine
from app.routes import auth, clients
from app.seed import seed

load_dotenv()

# Create tables
Base.metadata.create_all(bind=engine)
seed()

# Initialize FastAPI app
app = FastAPI(
    title="Login & Client Management API",
    description="API with bcrypt password hashing and client management",
    version="1.0.0"
)

# Configure CORS
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(clients.router)

@app.get("/")
def read_root():
    """Root endpoint."""
    return {
        "message": "Login & Client Management API",
        "version": "1.0.0",
        "docs": "/docs"
    }

@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
