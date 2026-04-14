"""
Encryption Middleware for FastAPI
Provides optional end-to-end encryption for sensitive payloads
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from cryptography.fernet import Fernet
import json
import os

class EncryptionMiddleware(BaseHTTPMiddleware):
    """
    Optional middleware to encrypt/decrypt request/response bodies
    Set X-Encrypt-Payload: true header to enable encryption for that request
    """
    
    def __init__(self, app):
        super().__init__(app)
        # Generate a key (in production, load from secure vault)
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        
    async def dispatch(self, request: Request, call_next):
        # Check if encryption is requested
        encrypt_payload = request.headers.get('X-Encrypt-Payload', 'false').lower() == 'true'
        
        # Process request
        request_body = await request.body()
        if encrypt_payload and request_body and request.method in ['POST', 'PUT', 'PATCH']:
            try:
                decrypted = self.cipher.decrypt(request_body)
                request._body = decrypted
            except Exception as e:
                print(f"⚠️  Decryption failed: {e}")
        
        # Process response
        response = await call_next(request)
        
        if encrypt_payload and response.body:
            try:
                encrypted_body = self.cipher.encrypt(response.body)
                response.body = encrypted_body
                response.headers['X-Encrypted'] = 'true'
            except Exception as e:
                print(f"⚠️  Response encryption failed: {e}")
        
        return response
