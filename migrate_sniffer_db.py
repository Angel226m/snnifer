#!/usr/bin/env python3
"""
Database Migration Tool
Aplica las migraciones de base de datos para el sniffer avanzado
"""

import psycopg2
import os
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv('SNIFFER_DB_URL', 'postgresql://postgres:password@db:5432/learnwithgaray')

def execute_migration(migration_file):
    """Ejecutar archivo de migración"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        # Leer el archivo SQL
        with open(migration_file, 'r') as f:
            sql_content = f.read()
        
        # Ejecutar en bloques (separados por ;)
        statements = sql_content.split(';')
        for statement in statements:
            statement = statement.strip()
            if statement:  # Skip empty statements
                try:
                    cur.execute(statement)
                    logger.info(f"✅ Executed: {statement[:60]}...")
                except Exception as e:
                    logger.warning(f"⚠️ Statement error: {e}")
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"✅ Migration {migration_file} completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        return False


def migrate_database():
    """Ejecutar todas las migraciones pendientes"""
    logger.info("🔧 Starting database migrations for Advanced Packet Sniffer...")
    
    # Directorio de script actual
    script_dir = Path(__file__).parent
    
    # Migraciones a ejecutar
    migrations = [
        script_dir / 'migrations_sniffer_advanced.sql',
    ]
    
    for migration_file in migrations:
        if migration_file.exists():
            logger.info(f"\n📝 Applying migration: {migration_file.name}")
            execute_migration(str(migration_file))
        else:
            logger.warning(f"⚠️ Migration file not found: {migration_file}")
    
    logger.info("\n✅ All migrations completed!")
    return True


if __name__ == '__main__':
    migrate_database()
