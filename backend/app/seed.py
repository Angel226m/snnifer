from app.database import SessionLocal
from app import models


def seed():
    """Verify database seed - init-db.sql already preloads all demo data"""
    db = SessionLocal()
    try:
        user = db.query(models.User).filter_by(email="angel@gmail.com").first()
        clients = db.query(models.Client).filter_by(user_id=user.id).count() if user else 0
        
        if user and clients >= 6:
            print(f"✅ Base de datos inicializada: {user.email} + {clients} clientes")
            return
        
        if not user:
            print("⚠️ Usuario demo no encontrado (init-db.sql debería haberlo creado)")
        else:
            print(f"⚠️ Faltan clientes demo ({clients}/6 encontrados)")
            
    except Exception as e:
        print(f"⚠️ Seed check: {e}")
    finally:
        db.close()
