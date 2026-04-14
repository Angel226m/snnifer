from sqlalchemy import Column, Integer, String, VARCHAR, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    clients = relationship("Client", back_populates="user", cascade="all, delete-orphan")

class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    surname = Column(String(100), nullable=False)
    age = Column(Integer, nullable=True)
    dni = Column(VARCHAR(8), nullable=False)
    phone = Column(VARCHAR(9), nullable=False)
    email = Column(String(100), nullable=True)
    address = Column(Text, nullable=True)
    encrypted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="clients")
