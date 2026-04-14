from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from jose import JWTError, jwt
import os

from app import crud, schemas
from app.database import get_db

router = APIRouter(prefix="/clients", tags=["clients"])

SECRET_KEY = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
ALGORITHM = "HS256"

def get_current_user_id(authorization: str = Header(None), db: Session = Depends(get_db)):
    """Extract user ID from JWT token."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

    return int(user_id)

@router.get("", response_model=schemas.ClientListResponse)
def get_clients(
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    """Get all clients for authenticated user."""
    user_id = get_current_user_id(authorization, db)

    clients = crud.get_clients(db, user_id=user_id)

    return {
        "clients": clients,
        "total": len(clients)
    }

@router.post("", response_model=schemas.ClientResponse)
def create_client(
    client: schemas.ClientCreate,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    """Create a new client."""
    user_id = get_current_user_id(authorization, db)

    db_client = crud.create_client(db, client=client, user_id=user_id)

    return db_client

@router.get("/{client_id}", response_model=schemas.ClientResponse)
def get_client(
    client_id: int,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    """Get a specific client."""
    user_id = get_current_user_id(authorization, db)

    db_client = crud.get_client_by_id(db, client_id=client_id, user_id=user_id)
    if not db_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )

    return db_client

@router.put("/{client_id}", response_model=schemas.ClientResponse)
def update_client(
    client_id: int,
    client: schemas.ClientBase,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    """Update a client's information."""
    user_id = get_current_user_id(authorization, db)

    db_client = crud.get_client_by_id(db, client_id=client_id, user_id=user_id)
    if not db_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )

    # Log the update for audit trail
    print(f"[AUDIT] User {user_id} updating client {client_id}")
    
    db_client = crud.update_client(db, db_client=db_client, client=client)

    return db_client

@router.delete("/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_client(
    client_id: int,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    """Delete a client. Requires authentication."""
    user_id = get_current_user_id(authorization, db)

    db_client = crud.get_client_by_id(db, client_id=client_id, user_id=user_id)
    if not db_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )

    # Log deletion for audit trail
    client_name = f"{db_client.name} {db_client.surname}"
    print(f"[AUDIT] User {user_id} deleting client {client_id}: {client_name}")
    
    crud.delete_client(db, db_client=db_client)
    
    # Return 204 No Content
    return None
