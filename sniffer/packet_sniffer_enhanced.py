#!/usr/bin/env python3
"""
Advanced Packet Sniffer MEJORADO - Similar a Wireshark
Captura COMPLETA de paquetes en TODAS las capas OSI (Layer 2-7)
Analisis detallado, estadisticas completas y almacenamiento en PostgreSQL
"""

import threading
import json
import logging
import psycopg2
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, ARP, IPv6, Ether, get_if_list
import re
from datetime import datetime
import os
import time
import gzip
import zlib
import struct
import socket
from collections import defaultdict
import traceback

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv('SNIFFER_DB_URL', 'postgresql://postgres:password@db:5432/learnwithgaray')

# ============================================================
# ESTADISTICAS GLOBALES - Tipo Wireshark
# ============================================================
class NetworkStats:
    """Mantiene estadisticas globales de trafico como Wireshark"""
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_stats = defaultdict(lambda: {'count': 0, 'bytes': 0})
        self.conversation_flows = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'first_seen': None, 'last_seen': None})
        self.ip_stats = defaultdict(lambda: {'sent': 0, 'received': 0, 'bytes_sent': 0, 'bytes_received': 0})
        self.port_stats = defaultdict(lambda: {'count': 0, 'bytes': 0, 'protocols': defaultdict(int)})
        self.dns_queries = defaultdict(list)
        self.tcp_streams = {}
        self.http_requests = []
        self.tls_handshakes = []
        
    def update_packet_stats(self, protocol, packet_size, src_ip, dst_ip, sport=None, dport=None):
        """Actualizar estadisticas globales"""
        self.total_packets += 1
        self.total_bytes += packet_size
        self.protocol_stats[protocol]['count'] += 1
        self.protocol_stats[protocol]['bytes'] += packet_size
        
        # Flow conversations
        if sport and dport:
            flow_key = tuple(sorted([f"{src_ip}:{sport}", f"{dst_ip}:{dport}"]))
            self.conversation_flows[flow_key]['packets'] += 1
            self.conversation_flows[flow_key]['bytes'] += packet_size
            now = datetime.now()
            if not self.conversation_flows[flow_key]['first_seen']:
                self.conversation_flows[flow_key]['first_seen'] = now
            self.conversation_flows[flow_key]['last_seen'] = now
        
        # IP stats
        self.ip_stats[src_ip]['sent'] += 1
        self.ip_stats[src_ip]['bytes_sent'] += packet_size
        self.ip_stats[dst_ip]['received'] += 1
        self.ip_stats[dst_ip]['bytes_received'] += packet_size
        
        # Port stats
        if dport:
            self.port_stats[dport]['count'] += 1
            self.port_stats[dport]['bytes'] += packet_size
            self.port_stats[dport]['protocols'][protocol] += 1
    
    def get_summary(self):
        """Obtener resumen tipo Wireshark"""
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'num_protocols': len(self.protocol_stats),
            'num_flows': len(self.conversation_flows),
            'num_unique_ips': len(self.ip_stats),
            'num_open_ports': len(self.port_stats),
            'num_http_requests': len(self.http_requests),
            'num_dns_queries': sum(len(v) for v in self.dns_queries.values()),
            'num_tls_handshakes': len(self.tls_handshakes)
        }


# ============================================================
# PARSER DE PAQUETES AVANZADO
# ============================================================
class AdvancedPacketParser:
    """Parsea paquetes en TODAS las capas: Link, Network, Transport, Application"""
    
    @staticmethod
    def parse_ethernet_frame(packet):
        """Parsear capa 2 - Ethernet"""
        try:
            if not Ether in packet:
                return None
            eth = packet[Ether]
            return {
                'src_mac': eth.src,
                'dst_mac': eth.dst,
                'type': eth.type,
                'type_name': 'IPv4' if eth.type == 0x0800 else ('IPv6' if eth.type == 0x86DD else ('ARP' if eth.type == 0x0806 else 'OTHER'))
            }
        except Exception as e:
            logger.debug(f"Ethernet parse error: {e}")
            return None
    
    @staticmethod
    def parse_ip_layer(packet):
        """Parsear capa 3 - IP"""
        try:
            if IP in packet:
                ip = packet[IP]
                return {
                    'version': ip.version,
                    'header_length': ip.ihl * 4,
                    'ttl': ip.ttl,
                    'proto': ip.proto,
                    'proto_name': 'TCP' if ip.proto == 6 else ('UDP' if ip.proto == 17 else ('ICMP' if ip.proto == 1 else 'OTHER')),
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'total_length': ip.len,
                    'flags': str(ip.flags),
                    'fragment_offset': ip.frag,
                    'identification': ip.id,
                }
            elif IPv6 in packet:
                ip = packet[IPv6]
                return {
                    'version': 6,
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'traffic_class': ip.tc,
                    'flow_label': ip.flow,
                    'payload_length': ip.plen,
                    'next_header': ip.nh,
                    'hop_limit': ip.hlim,
                }
        except Exception as e:
            logger.debug(f"IP parse error: {e}")
        return None
    
    @staticmethod
    def parse_tcp_layer(packet):
        """Parsear capa 4 - TCP"""
        try:
            if TCP not in packet:
                return None
            tcp = packet[TCP]
            flags_dict = {
                'F': tcp.flags.F,  # FIN
                'S': tcp.flags.S,  # SYN
                'A': tcp.flags.A,  # ACK
                'P': tcp.flags.P,  # PUSH
                'R': tcp.flags.R,  # RESET
                'U': tcp.flags.U,  # URGENT
            }
            flags_str = ''.join([k for k, v in flags_dict.items() if v])
            
            return {
                'sport': tcp.sport,
                'dport': tcp.dport,
                'seq': tcp.seq,
                'ack': tcp.ack,
                'flags': flags_str if flags_str else 'NONE',
                'window_size': tcp.window,
                'urgent_pointer': tcp.urgptr,
                'options': str(tcp.options) if tcp.options else [],
                'payload_length': len(tcp.payload) if tcp.payload else 0,
            }
        except Exception as e:
            logger.debug(f"TCP parse error: {e}")
        return None
    
    @staticmethod
    def parse_udp_layer(packet):
        """Parsear capa 4 - UDP"""
        try:
            if UDP not in packet:
                return None
            udp = packet[UDP]
            return {
                'sport': udp.sport,
                'dport': udp.dport,
                'length': udp.len,
                'checksum': udp.chksum,
                'payload_length': len(udp.payload) if udp.payload else 0,
            }
        except Exception as e:
            logger.debug(f"UDP parse error: {e}")
        return None
    
    @staticmethod
    def parse_dns_layer(packet):
        """Parsear capa 7 - DNS"""
        try:
            if DNS not in packet:
                return None
            dns = packet[DNS]
            queries = []
            answers = []
            
            if dns.qdcount > 0 and DNSQR in packet:
                for i in range(dns.qdcount):
                    q = dns.qd
                    queries.append({
                        'name': str(q.qname),
                        'type': q.qtype,
                        'class': q.qclass,
                    })
            
            # Parsear respuestas
            if dns.ancount > 0:
                rr = dns.an
                while rr:
                    answers.append({
                        'name': str(rr.rrname),
                        'type': rr.type,
                        'rdata': str(rr.rdata),
                        'ttl': rr.ttl,
                    })
                    rr = rr.payload if hasattr(rr, 'payload') and hasattr(rr.payload, 'rrname') else None
            
            return {
                'is_response': dns.qr,
                'query_count': dns.qdcount,
                'answer_count': dns.ancount,
                'queries': queries,
                'answers': answers,
            }
        except Exception as e:
            logger.debug(f"DNS parse error: {e}")
        return None
    
    @staticmethod
    def parse_http_layer(payload):
        """Parsear capa 7 - HTTP"""
        try:
            if not isinstance(payload, (bytes, bytearray)):
                return None
            
            # Detectar y descomprimir
            decompressed, compression = AdvancedPacketParser.try_decompress(payload)
            
            try:
                data = decompressed.decode('utf-8', errors='ignore')
            except:
                return None
            
            lines = data.split('\r\n')
            if not lines or len(lines) < 1:
                return None
            
            first_line = lines[0]
            
            # Detectar tipo
            is_request = any(first_line.startswith(m) for m in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT'])
            is_response = first_line.startswith('HTTP/')
            
            if not (is_request or is_response):
                return None
            
            result = {
                'is_request': is_request,
                'is_response': is_response,
                'raw_line': first_line,
                'compression': compression,
                'headers': {},
                'body_size': 0,
            }
            
            # Parsear request line
            if is_request:
                parts = first_line.split(' ')
                if len(parts) >= 3:
                    result['method'] = parts[0]
                    result['path'] = parts[1]
                    result['version'] = parts[2]
            
            # Parsear response line
            elif is_response:
                parts = first_line.split(' ')
                if len(parts) >= 3:
                    result['version'] = parts[0]
                    try:
                        result['status_code'] = int(parts[1])
                    except:
                        pass
                    result['reason'] = ' '.join(parts[2:])
            
            # Parsear headers
            body_start = None
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, val = line.split(':', 1)
                    result['headers'][key.strip()] = val.strip()
            
            # Parsear body
            if body_start and body_start < len(lines):
                body = '\r\n'.join(lines[body_start:]).strip()
                result['body_size'] = len(body)
                if body:
                    try:
                        result['body_preview'] = json.loads(body)
                    except:
                        result['body_preview'] = body[:200]
            
            return result
        except Exception as e:
            logger.debug(f"HTTP parse error: {e}")
        return None
    
    @staticmethod
    def try_decompress(payload):
        """Intentar descomprimir gzip, deflate, brotli"""
        try:
            if payload.startswith(b'\x1f\x8b'):  # Gzip
                return gzip.decompress(payload), 'GZIP'
        except:
            pass
        
        try:
            if payload.startswith(b'\x78'):  # Deflate
                return zlib.decompress(payload), 'DEFLATE'
        except:
            pass
        
        try:
            import brotli
            return brotli.decompress(payload), 'BROTLI'
        except:
            pass
        
        return payload, None


# ============================================================
# SNIFFER PRINCIPAL
# ============================================================
class AdvancedPacketSniffer:
    """Sniffer avanzado capturando TODAS las capas"""
    
    def __init__(self):
        self.running = False
        self.stats = NetworkStats()
        self.seen_packets = {}
        self.db_connection = None
        self.packet_buffer = []
        
    def get_db_connection(self):
        """Obtener conexion a base de datos"""
        try:
            conn = psycopg2.connect(DATABASE_URL)
            return conn
        except Exception as e:
            logger.error(f"DB Connection Error: {e}")
            return None
    
    def save_packet_info(self, packet_data):
        """Guardar informacion completa del paquete en BD"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return False
            
            cur = conn.cursor()
            
            # Insertar en tabla de paquetes capturados
            cur.execute("""
                INSERT INTO captured_packets 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, 
                 packet_size, layer2_info, layer3_info, layer4_info, 
                 layer7_info, raw_payload, packet_flags)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                datetime.now(),
                packet_data.get('src_ip'),
                packet_data.get('dst_ip'),
                packet_data.get('src_port'),
                packet_data.get('dst_port'),
                packet_data.get('protocol'),
                packet_data.get('packet_size'),
                json.dumps(packet_data.get('layer2')),
                json.dumps(packet_data.get('layer3')),
                json.dumps(packet_data.get('layer4')),
                json.dumps(packet_data.get('layer7')),
                packet_data.get('raw_payload'),
                json.dumps(packet_data.get('flags'))
            ))
            
            conn.commit()
            cur.close()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Save error: {e}")
            return False
    
    def process_packet(self, packet):
        """Procesar paquete en TODAS las capas como Wireshark"""
        try:
            # Obtener timestamp
            packet_time = datetime.now()
            
            # Layer 2 - Ethernet
            layer2 = AdvancedPacketParser.parse_ethernet_frame(packet)
            
            # Layer 3 - IP
            layer3 = AdvancedPacketParser.parse_ip_layer(packet)
            if not layer3:
                return
            
            src_ip = layer3.get('src_ip')
            dst_ip = layer3.get('dst_ip')
            
            # Layer 4 - TCP/UDP
            layer4 = None
            protocol = None
            src_port = None
            dst_port = None
            
            if TCP in packet:
                layer4 = AdvancedPacketParser.parse_tcp_layer(packet)
                protocol = 'TCP'
                src_port = layer4.get('sport') if layer4 else None
                dst_port = layer4.get('dport') if layer4 else None
            elif UDP in packet:
                layer4 = AdvancedPacketParser.parse_udp_layer(packet)
                protocol = 'UDP'
                src_port = layer4.get('sport') if layer4 else None
                dst_port = layer4.get('dport') if layer4 else None
            elif ICMP in packet:
                protocol = 'ICMP'
            else:
                protocol = layer3.get('proto_name', 'OTHER')
            
            packet_size = len(packet)
            
            # Layer 7 - DNS, HTTP, etc
            layer7 = None
            if DNS in packet:
                layer7 = {
                    'protocol': 'DNS',
                    'data': AdvancedPacketParser.parse_dns_layer(packet)
                }
            elif Raw in packet and protocol == 'TCP' and dst_port in [80, 8000, 3000, 5000]:
                layer7 = {
                    'protocol': 'HTTP',
                    'data': AdvancedPacketParser.parse_http_layer(bytes(packet[Raw].load))
                }
            elif Raw in packet and protocol == 'TCP' and dst_port == 443:
                # TLS/SSL
                payload = bytes(packet[Raw].load)
                if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
                    layer7 = {
                        'protocol': 'TLS',
                        'data': {'tls_record_type': 'Handshake', 'version': f'{payload[2]}'}
                    }
            
            # Actualizar estadisticas
            self.stats.update_packet_stats(protocol, packet_size, src_ip, dst_ip, src_port, dst_port)
            
            # Construir paquete completo
            packet_data = {
                'timestamp': packet_time,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'packet_size': packet_size,
                'layer2': layer2,
                'layer3': layer3,
                'layer4': layer4,
                'layer7': layer7,
                'raw_payload': None,
                'flags': {
                    'is_encrypted': dst_port == 443 or src_port == 443,
                    'is_http': dst_port in [80, 8000, 3000, 5000],
                    'is_dns': dst_port == 53 or src_port == 53,
                }
            }
            
            # Log detallado
            if layer7:
                proto = layer7.get('protocol')
                if proto == 'HTTP' and layer7.get('data', {}).get('is_request'):
                    method = layer7.get('data', {}).get('method', 'UNKNOWN')
                    path = layer7.get('data', {}).get('path', '/')
                    logger.info(f"🔵 HTTP REQUEST: {method} {path} from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                    self.stats.http_requests.append(packet_data)
                elif proto == 'DNS':
                    logger.info(f"🟡 DNS QUERY from {src_ip}:{src_port}")
                elif proto == 'TLS':
                    logger.info(f"🔒 TLS HANDSHAKE from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                    self.stats.tls_handshakes.append(packet_data)
            else:
                logger.info(f"📦 {protocol}: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({packet_size} bytes)")
            
            # Guardar en base de datos
            self.save_packet_info(packet_data)
            
        except Exception as e:
            logger.error(f"Packet processing error: {e}\n{traceback.format_exc()}")
    
    def start_sniffing(self, interface=None, filter_str=None):
        """Iniciar captura de paquetes"""
        self.running = True
        try:
            if not interface:
                # Auto-detectar interfaz
                interfaces = get_if_list()
                interface = interfaces[0] if interfaces else None
            
            logger.info(f"🎯 Starting packet capture on interface: {interface}")
            logger.info(f"📊 Press Ctrl+C to stop and see statistics")
            
            # Sniff packets
            sniff(
                prn=self.process_packet,
                iface=interface,
                filter=filter_str or "ip",
                store=False
            )
        except KeyboardInterrupt:
            logger.info("\n\n📊 === CAPTURE STATISTICS ===")
            self.print_statistics()
        except Exception as e:
            logger.error(f"Sniffing error: {e}\n{traceback.format_exc()}")
        finally:
            self.running = False
    
    def print_statistics(self):
        """Mostrar estadisticas completas tipo Wireshark"""
        summary = self.stats.get_summary()
        
        print("\n" + "="*80)
        print("CAPTURE SUMMARY".center(80))
        print("="*80)
        print(f"Total Packets Captured: {summary['total_packets']}")
        print(f"Total Bytes Captured:  {summary['total_bytes']:,} bytes")
        print(f"Unique Protocols:      {summary['num_protocols']}")
        print(f"Unique Conversations:  {summary['num_flows']}")
        print(f"Unique IP Addresses:   {summary['num_unique_ips']}")
        print(f"Unique Ports:          {summary['num_open_ports']}")
        print(f"HTTP Requests:         {summary['num_http_requests']}")
        print(f"DNS Queries:           {summary['num_dns_queries']}")
        print(f"TLS Handshakes:        {summary['num_tls_handshakes']}")
        
        print("\n" + "-"*80)
        print("PROTOCOL DISTRIBUTION")
        print("-"*80)
        for proto, stats in sorted(self.stats.protocol_stats.items(), key=lambda x: x[1]['count'], reverse=True):
            pct = (stats['count'] / summary['total_packets'] * 100) if summary['total_packets'] > 0 else 0
            print(f"  {proto:10} {stats['count']:6} packets ({pct:5.1f}%) {stats['bytes']:12,} bytes")
        
        print("\n" + "-"*80)
        print("TOP CONVERSATIONS (Flows)")
        print("-"*80)
        for flow, stats in sorted(self.stats.conversation_flows.items(), key=lambda x: x[1]['packets'], reverse=True)[:10]:
            duration = (stats['last_seen'] - stats['first_seen']).total_seconds() if stats['first_seen'] else 0
            print(f"  {flow[0]:30} ↔ {flow[1]:30} | Pkts: {stats['packets']:4} | Bytes: {stats['bytes']:10,} | Duration: {duration:.1f}s")
        
        print("\n" + "-"*80)
        print("TOP IP ADDRESSES")
        print("-"*80)
        for ip, stats in sorted(self.stats.ip_stats.items(), key=lambda x: x[1]['bytes_sent'] + x[1]['bytes_received'], reverse=True)[:10]:
            total_bytes = stats['bytes_sent'] + stats['bytes_received']
            print(f"  {ip:20} | Sent: {stats['bytes_sent']:12,} | Recv: {stats['bytes_received']:12,} | Total: {total_bytes:12,}")
        
        print("\n" + "-"*80)
        print("TOP PORTS")
        print("-"*80)
        for port, stats in sorted(self.stats.port_stats.items(), key=lambda x: x[1]['bytes'], reverse=True)[:15]:
            proto_str = ', '.join([f"{p}({c})" for p, c in stats['protocols'].items()])
            print(f"  Port {port:5} | Packets: {stats['count']:6} | Bytes: {stats['bytes']:12,} | Protocols: {proto_str}")
        
        print("\n" + "="*80)
        logger.info("✅ Statistics saved to database")


# Iniciar sniffer
if __name__ == '__main__':
    sniffer = AdvancedPacketSniffer()
    sniffer.start_sniffing()
