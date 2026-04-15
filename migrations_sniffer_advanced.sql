-- Migration: Add captured_packets table for advanced packet sniffing
-- Similar to Wireshark packet capture database

CREATE TABLE IF NOT EXISTS captured_packets (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Layer 3 - Network
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    
    -- Layer 4 - Transport
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(20) NOT NULL,
    
    -- Tamaños y información
    packet_size INTEGER NOT NULL,
    
    -- Capas OSI detalladas
    layer2_info JSONB,  -- Ethernet, MAC addresses
    layer3_info JSONB,  -- IP header details, TTL, flags, etc
    layer4_info JSONB,  -- TCP/UDP ports, flags, sequences
    layer7_info JSONB,  -- HTTP, DNS, TLS payloads
    
    -- Raw payload (pueden ser NULL para no llenar demasiado)
    raw_payload BYTEA,
    
    -- Flags y metadatos
    packet_flags JSONB,
    
    -- Indices para búsquedas rápidas
    CONSTRAINT captured_packets_unique UNIQUE (timestamp, src_ip, dst_ip, src_port, dst_port, protocol)
);

-- Indices para búsquedas rápidas tipo Wireshark
CREATE INDEX IF NOT EXISTS idx_captured_timestamp ON captured_packets(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_captured_src_ip ON captured_packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_captured_dst_ip ON captured_packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_captured_protocol ON captured_packets(protocol);
CREATE INDEX IF NOT EXISTS idx_captured_ports ON captured_packets(src_port, dst_port);
CREATE INDEX IF NOT EXISTS idx_captured_layer7 ON captured_packets USING GIN(layer7_info);
CREATE INDEX IF NOT EXISTS idx_captured_flags ON captured_packets USING GIN(packet_flags);

-- Tabla para estadísticas agregadas
CREATE TABLE IF NOT EXISTS packet_statistics (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total_packets BIGINT,
    total_bytes BIGINT,
    protocol VARCHAR(20),
    protocol_count INTEGER,
    protocol_bytes BIGINT,
    unique_ips INTEGER,
    unique_ports INTEGER,
    http_requests INTEGER,
    dns_queries INTEGER,
    tls_handshakes INTEGER,
    statistics_json JSONB
);

-- Tabla para flows/conversaciones
CREATE TABLE IF NOT EXISTS network_flows (
    id SERIAL PRIMARY KEY,
    timestamp_start TIMESTAMP NOT NULL,
    timestamp_end TIMESTAMP NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(20),
    packet_count INTEGER DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    flow_info JSONB,
    CONSTRAINT flows_unique UNIQUE (src_ip, dst_ip, src_port, dst_port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_flows_ips ON network_flows(src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_ports ON network_flows(src_port, dst_port);
CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON network_flows(timestamp_start, timestamp_end);

-- Tabla para HTTP requests capturados
CREATE TABLE IF NOT EXISTS http_captures (
    id SERIAL PRIMARY KEY,
    packet_id INTEGER REFERENCES captured_packets(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    method VARCHAR(20),
    path VARCHAR(1024),
    status_code INTEGER,
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    src_port INTEGER,
    dst_port INTEGER,
    headers JSONB,
    body_preview TEXT,
    body_size INTEGER,
    compression VARCHAR(20),
    is_encrypted BOOLEAN DEFAULT FALSE,
    http_info JSONB
);

CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_captures(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_http_method_path ON http_captures(method, path);
CREATE INDEX IF NOT EXISTS idx_http_status ON http_captures(status_code);

-- Tabla para DNS queries
CREATE TABLE IF NOT EXISTS dns_captures (
    id SERIAL PRIMARY KEY,
    packet_id INTEGER REFERENCES captured_packets(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    query_name VARCHAR(255),
    query_type VARCHAR(20),
    response TEXT,
    ttl INTEGER,
    is_response BOOLEAN,
    dns_info JSONB
);

CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_captures(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_captures(query_name);

-- Tabla para TLS handshakes
CREATE TABLE IF NOT EXISTS tls_captures (
    id SERIAL PRIMARY KEY,
    packet_id INTEGER REFERENCES captured_packets(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    src_port INTEGER,
    dst_port INTEGER,
    tls_version VARCHAR(20),
    cipher_suite VARCHAR(255),
    certificate_info JSONB,
    tls_record_type VARCHAR(20),
    tls_info JSONB
);

CREATE INDEX IF NOT EXISTS idx_tls_timestamp ON tls_captures(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_tls_version ON tls_captures(tls_version);

-- View para obtener resumen de capturas
CREATE OR REPLACE VIEW capture_summary AS
SELECT 
    COUNT(*) as total_packets,
    SUM(packet_size) as total_bytes,
    COUNT(DISTINCT protocol) as unique_protocols,
    COUNT(DISTINCT src_ip) + COUNT(DISTINCT dst_ip) as unique_ips,
    COUNT(DISTINCT src_port) + COUNT(DISTINCT dst_port) as unique_ports,
    MAX(timestamp) as last_capture,
    MIN(timestamp) as first_capture
FROM captured_packets;

-- View para top conversations
CREATE OR REPLACE VIEW top_conversations AS
SELECT 
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    COUNT(*) as packet_count,
    SUM(packet_size) as total_bytes,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen
FROM captured_packets
GROUP BY src_ip, dst_ip, src_port, dst_port, protocol
ORDER BY packet_count DESC;

-- View para estadísticas por protocolo
CREATE OR REPLACE VIEW protocol_stats AS
SELECT 
    protocol,
    COUNT(*) as packet_count,
    SUM(packet_size) as total_bytes,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM captured_packets), 2) as percentage
FROM captured_packets
GROUP BY protocol
ORDER BY packet_count DESC;
