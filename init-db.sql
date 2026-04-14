-- PostgreSQL Database Initialization Script
-- Crea tablas, índices e inserta datos demo

-- Crear extensiones
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tabla users
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla clients
CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    surname VARCHAR(255) NOT NULL,
    age INTEGER,
    dni VARCHAR(8) NOT NULL UNIQUE,
    phone VARCHAR(9) NOT NULL,
    email VARCHAR(255),
    address TEXT,
    encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla traffic_logs (para sniffer)
CREATE TABLE IF NOT EXISTS traffic_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    method VARCHAR(10),
    endpoint VARCHAR(255),
    status_code INTEGER,
    request_body JSONB,
    response_body JSONB,
    request_headers JSONB,
    response_headers JSONB,
    execution_time_ms FLOAT,
    is_encrypted BOOLEAN DEFAULT TRUE,
    encryption_type VARCHAR(50),
    vulnerabilities JSONB,
    user_agent VARCHAR(255),
    client_ip VARCHAR(45)
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_clients_user_id ON clients(user_id);
CREATE INDEX IF NOT EXISTS idx_clients_dni ON clients(dni);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_endpoint ON traffic_logs(endpoint);
CREATE INDEX IF NOT EXISTS idx_traffic_status ON traffic_logs(status_code);
CREATE INDEX IF NOT EXISTS idx_traffic_vuln ON traffic_logs USING GIN(vulnerabilities);

-- Insertar usuario demo (contraseña: angel22, hasheada con bcrypt 5 rounds)
-- Hash: $2b$05$WIwzY4SSA7qhrL/qIQyHtOtgtjG165p83Z6Qg2bGUP7y3PghWduYi
INSERT INTO users (email, password_hash, created_at)
VALUES (
    'angel@gmail.com',
    '$2b$05$WIwzY4SSA7qhrL/qIQyHtOtgtjG165p83Z6Qg2bGUP7y3PghWduYi',
    NOW()
)
ON CONFLICT (email) DO NOTHING;

-- Insertar clientes demo
INSERT INTO clients (user_id, name, surname, age, dni, phone, email, address, encrypted, created_at)
VALUES (
    (SELECT id FROM users WHERE email = 'angel@gmail.com'),
    'Juan', 'García', 28, '12345678', '612345678', 'juan.garcia@mail.com', 'Calle Mayor 1, Madrid', FALSE, NOW()
)
ON CONFLICT (dni) DO NOTHING;

INSERT INTO clients (user_id, name, surname, age, dni, phone, email, address, encrypted, created_at)
VALUES (
    (SELECT id FROM users WHERE email = 'angel@gmail.com'),
    'María', 'López', 35, '87654321', '698765432', 'maria.lopez@mail.com', 'Av. Libertad 5, Barcelona', FALSE, NOW()
)
ON CONFLICT (dni) DO NOTHING;

INSERT INTO clients (user_id, name, surname, age, dni, phone, email, address, encrypted, created_at)
VALUES (
    (SELECT id FROM users WHERE email = 'angel@gmail.com'),
    'Carlos', 'Martínez', 42, '11223344', '655112233', 'carlos.mtz@mail.com', 'C/ Rosales 10, Valencia', FALSE, NOW()
)
ON CONFLICT (dni) DO NOTHING;

INSERT INTO clients (user_id, name, surname, age, dni, phone, email, address, encrypted, created_at)
VALUES (
    (SELECT id FROM users WHERE email = 'angel@gmail.com'),
    'Ana', 'Fernández', 31, '44332211', '677443322', 'ana.fern@mail.com', 'Plaza España 3, Sevilla', FALSE, NOW()
)
ON CONFLICT (dni) DO NOTHING;

INSERT INTO clients (user_id, name, surname, age, dni, phone, email, address, encrypted, created_at)
VALUES (
    (SELECT id FROM users WHERE email = 'angel@gmail.com'),
    'Pedro', 'Sánchez', 50, '55667788', '634556677', NULL, 'C/ Colón 8, Zaragoza', FALSE, NOW()
)
ON CONFLICT (dni) DO NOTHING;

INSERT INTO clients (user_id, name, surname, age, dni, phone, email, address, encrypted, created_at)
VALUES (
    (SELECT id FROM users WHERE email = 'angel@gmail.com'),
    'Laura', 'Jiménez', 26, '99887766', '611998877', 'laura.jim@mail.com', 'Av. Diagonal 200, Barcelona', FALSE, NOW()
)
ON CONFLICT (dni) DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
