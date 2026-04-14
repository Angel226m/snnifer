from sqlalchemy.orm import Session
from app import models, schemas, crypto

# ============= USER CRUD =============

def create_user(db: Session, user: schemas.UserCreate):
    """Create a new user."""
    password_hash = crypto.hash_password(user.password)
    db_user = models.User(email=user.email, password_hash=password_hash)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_email(db: Session, email: str):
    """Get user by email."""
    return db.query(models.User).filter(models.User.email == email).first()

def get_user_by_id(db: Session, user_id: int):
    """Get user by ID."""
    return db.query(models.User).filter(models.User.id == user_id).first()

# ============= CLIENT CRUD =============

def create_client(db: Session, client: schemas.ClientCreate, user_id: int):
    """Create a new client."""
    db_client = models.Client(
        user_id=user_id,
        name=client.name,
        surname=client.surname,
        age=client.age,
        dni=client.dni,
        phone=client.phone,
        email=client.email,
        address=client.address,
        encrypted=False,
    )
    db.add(db_client)
    db.commit()
    db.refresh(db_client)
    return db_client

def get_clients(db: Session, user_id: int):
    """Get all clients for a user."""
    return db.query(models.Client).filter(models.Client.user_id == user_id).all()

def get_client_by_id(db: Session, client_id: int, user_id: int):
    """Get client by ID."""
    return db.query(models.Client).filter(
        models.Client.id == client_id,
        models.Client.user_id == user_id
    ).first()

def update_client(db: Session, db_client: models.Client, client: schemas.ClientBase):
    """Update a client."""
    db_client.name = client.name
    db_client.surname = client.surname
    db_client.age = client.age
    db_client.dni = client.dni
    db_client.phone = client.phone
    db_client.email = client.email
    db_client.address = client.address
    db.commit()
    db.refresh(db_client)
    return db_client

def delete_client(db: Session, db_client: models.Client):
    """Delete a client."""
    db.delete(db_client)
    db.commit()
