#!/usr/bin/env python3
"""
Simulate normal TURN user behavior
- Request a relay port via UDP allocation
- Forward a DNS query request to 8.8.8.8:53 through this relay port
- Periodically send refresh
- Send DNS requests again
"""

import socket
import struct
import time
import argparse
import sys
import os
import threading

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TURN_UTILS_DIR = os.path.join(CURRENT_DIR, "turn_utils")

for path in (CURRENT_DIR, TURN_UTILS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from turn_utils import (
    create_permission,
    channel_bind,
    channel_data,
    resolve_server_address,
    resolve_peer_address
)
from turn_utils.test_turn_capabilities import allocate_with_fallback
from turn_utils.turn_client import (
    STUN_ATTR_USERNAME,
    STUN_ATTR_REALM,
    STUN_ATTR_NONCE,
    STUN_ATTR_MESSAGE_INTEGRITY,
    STUN_ATTR_FINGERPRINT,
    STUN_MAGIC_COOKIE
)
# 直接从turn_client导入这些函数
import turn_utils.turn_client as turn_client
gen_tid = turn_client.gen_tid
stun_attr = turn_client.stun_attr
build_msg = turn_client.build_msg
parse_attrs = turn_client.parse_attrs
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

# STUN/TURN Refresh 常量（RFC 8656）
STUN_REFRESH_REQUEST = 0x0004
STUN_REFRESH_SUCCESS_RESPONSE = 0x0104
STUN_REFRESH_ERROR_RESPONSE = 0x0114
STUN_ATTR_LIFETIME = 0x000D

def refresh_allocation(sock, nonce, realm, integrity_key, server_address, username=None, lifetime=None, mi_algorithm=None):
    """
    Refresh TURN allocation
    
    Args:
        sock: TURN socket
        nonce: Authentication nonce
        realm: Authentication realm
        integrity_key: Integrity key
        server_address: TURN server address
        username: Username
        lifetime: Requested lifetime (seconds), None means use default
        mi_algorithm: Message integrity algorithm type ('sha256', 'sha1', 'both', or None)
    
    Returns:
        (success, lifetime_value) or (False, None)
    """
    from turn_utils.turn_client import (
        build_msg_with_short_term_credential,
        build_msg_with_short_term_credential_sha256_only,
        build_msg_with_short_term_credential_sha1_only,
        USERNAME
    )
    
    print(f"[+] Refreshing allocation...")
    
    auth_username = username or USERNAME
    
    tid = gen_tid()
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
    ]
    
    # Add REALM and NONCE (if provided)
    if realm is not None:
        attrs.append(stun_attr(STUN_ATTR_REALM, realm))
    if nonce is not None:
        attrs.append(stun_attr(STUN_ATTR_NONCE, nonce))
    
    # If lifetime is specified, add LIFETIME attribute
    if lifetime is not None:
        attrs.append(stun_attr(STUN_ATTR_LIFETIME, struct.pack("!I", lifetime)))
    
    # Short-term credentials (nonce and realm are None) must use the algorithm used by the server in the initial response
    if nonce is None and realm is None:
        if mi_algorithm == 'sha256':
            req = build_msg_with_short_term_credential_sha256_only(STUN_REFRESH_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        elif mi_algorithm == 'sha1':
            req = build_msg_with_short_term_credential_sha1_only(STUN_REFRESH_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        else:
            req = build_msg_with_short_term_credential(STUN_REFRESH_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    else:
        req = build_msg(STUN_REFRESH_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    
    # Check socket type: TCP or UDP
    is_tcp_socket = False
    if hasattr(sock, '_sslobj') or sock.__class__.__name__ == 'SSLSocket':
        is_tcp_socket = True
    elif hasattr(sock, 'type'):
        try:
            sock_type = sock.type
            if (sock_type == socket.SOCK_STREAM or 
                (hasattr(sock_type, 'value') and getattr(sock_type, 'value', None) == 1) or
                int(sock_type) == 1):
                is_tcp_socket = True
        except (ValueError, TypeError, AttributeError):
            pass
    
    if not is_tcp_socket:
        try:
            sock.getpeername()
            is_tcp_socket = True
        except (AttributeError, OSError, socket.error):
            pass
    
    try:
        if is_tcp_socket:
            sock.send(req)
            sock.settimeout(10)
            data = sock.recv(2000)
        else:
            sock.sendto(req, server_address)
            sock.settimeout(10)
            data, _ = sock.recvfrom(2000)
        
        msg_type, tid, attrs = parse_attrs(data)
        
        if msg_type == STUN_REFRESH_SUCCESS_RESPONSE:
            # Parse LIFETIME attribute
            lifetime_value = None
            if STUN_ATTR_LIFETIME in attrs:
                lifetime_value = struct.unpack("!I", attrs[STUN_ATTR_LIFETIME])[0]
                print(f"[+] Refresh successful, lifetime: {lifetime_value} seconds")
            else:
                print(f"[+] Refresh successful (default lifetime)")
            return True, lifetime_value
        elif msg_type == STUN_REFRESH_ERROR_RESPONSE:
            error_code = attrs.get(9)  # STUN_ATTR_ERROR_CODE
            if error_code:
                if len(error_code) >= 4:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    error_text = error_code[4:].decode('utf-8', errors='ignore')
                    print(f"[-] Refresh failed: {error_class}{error_number:02d} {error_text}")
                else:
                    error_text = error_code[3:].decode('utf-8', errors='ignore')
                    print(f"[-] Refresh failed: {error_text}")
            else:
                print(f"[-] Refresh failed: Unknown error")
            return False, None
        else:
            print(f"[-] Unexpected response type: 0x{msg_type:04x}")
            return False, None
    except socket.timeout:
        print(f"[-] Refresh timeout")
        return False, None
    except Exception as e:
        print(f"[-] Refresh error: {e}")
        return False, None

def build_dns_query(domain, query_type=1):
    """
    Build DNS query packet
    query_type: 1=A record, 28=AAAA record
    """
    transaction_id = int(time.time()) & 0xFFFF
    flags = 0x0100  # Standard query
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0
    
    header = struct.pack("!HHHHHH", transaction_id, flags, questions, 
                       answer_rrs, authority_rrs, additional_rrs)
    
    # Build query name
    query_name = b""
    for part in domain.split('.'):
        query_name += struct.pack("!B", len(part)) + part.encode()
    query_name += b"\x00"  # End marker
    
    # Query type and class
    query_type_class = struct.pack("!HH", query_type, 1)  # IN class
    
    return header + query_name + query_type_class, transaction_id

def parse_dns_response(data):
    """Parse DNS response"""
    if len(data) < 12:
        return None
        
    # Parse header
    transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = \
        struct.unpack("!HHHHHH", data[:12])
    
    print(f"[+] DNS Response - ID: {transaction_id}, Flags: 0x{flags:04x}")
    print(f"[+] Questions: {questions}, Answers: {answer_rrs}")
    
    # Parse question section
    pos = 12
    for _ in range(questions):
        # Skip query name
        while pos < len(data) and data[pos] != 0:
            pos += data[pos] + 1
        pos += 5  # Skip end marker and type, class
        
    # Parse answer section
    answers = []
    for _ in range(answer_rrs):
        if pos >= len(data):
            break
            
        # Parse name (may be compressed pointer)
        name_start = pos
        if data[pos] & 0xC0 == 0xC0:  # Compressed pointer
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
            
        if pos + 10 > len(data):
            break
            
        # Parse resource record
        query_type, query_class, ttl, data_length = \
            struct.unpack("!HHIH", data[pos:pos+10])
        pos += 10
        
        if pos + data_length > len(data):
            break
            
        rdata = data[pos:pos+data_length]
        pos += data_length
        
        answers.append({
            'type': query_type,
            'class': query_class,
            'ttl': ttl,
            'data': rdata
        })
        
    return {
        'transaction_id': transaction_id,
        'flags': flags,
        'answers': answers
    }

def send_dns_query_and_receive(sock, channel_number, dns_server_ip, dns_server_port, server_address, domain="www.example.com", timeout=10):
    """Send DNS query through TURN channel and receive response"""
    print(f"[+] Sending DNS query for {domain} to {dns_server_ip}:{dns_server_port}")
    
    # Build DNS query packet
    query_packet, transaction_id = build_dns_query(domain)
    
    # Send query through TURN channel
    if not channel_data(sock, channel_number, query_packet, server_address):
        print(f"[-] Failed to send DNS query")
        return None
    
    print(f"[+] DNS query sent (transaction ID: {transaction_id})")
    print(f"[+] Waiting for DNS response...")
    
    # Receive response
    try:
        sock.settimeout(timeout)
        if hasattr(sock, '_sslobj') or sock.__class__.__name__ == 'SSLSocket' or (hasattr(sock, 'type') and sock.type == socket.SOCK_STREAM):
            data = sock.recv(1024)
        else:
            data, addr = sock.recvfrom(1024)
        
        # Check if it's a ChannelData message
        if len(data) >= 4:
            channel_number_received = struct.unpack("!H", data[:2])[0]
            data_length = struct.unpack("!H", data[2:4])[0]
            
            if channel_number_received == channel_number and len(data) >= 4 + data_length:
                dns_data = data[4:4+data_length]
                response = parse_dns_response(dns_data)
                if response:
                    print(f"[+] DNS response received:")
                    print(f"    Transaction ID: {response['transaction_id']}")
                    print(f"    Flags: 0x{response['flags']:04x}")
                    print(f"    Answers: {len(response['answers'])}")
                    
                    # Parse and display answers
                    for i, answer in enumerate(response['answers']):
                        print(f"    Answer {i+1}:")
                        print(f"      Type: {answer['type']} ({'A' if answer['type'] == 1 else 'AAAA' if answer['type'] == 28 else 'Other'})")
                        print(f"      TTL: {answer['ttl']}")
                        
                        if answer['type'] == 1:  # A record
                            if len(answer['data']) == 4:
                                ip = socket.inet_ntoa(answer['data'])
                                print(f"      A Record: {ip}")
                        elif answer['type'] == 28:  # AAAA record
                            if len(answer['data']) == 16:
                                ipv6 = socket.inet_ntop(socket.AF_INET6, answer['data'])
                                print(f"      AAAA Record: {ipv6}")
                        else:
                            print(f"      Data: {answer['data'].hex()}")
                    
                    return response
                else:
                    print(f"[-] Failed to parse DNS response")
                    return None
            else:
                print(f"[-] Invalid channel data format")
                return None
        else:
            print(f"[-] Response too short")
            return None
            
    except socket.timeout:
        print(f"[+] No DNS response received within timeout")
        return None
    except Exception as e:
        print(f"[-] Error receiving DNS response: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Simulate normal TURN user behavior')
    parser.add_argument('--turn-server', help='TURN server address (hostname or IP)')
    parser.add_argument('--turn-port', type=int, help='TURN server port')
    parser.add_argument('--username', help='TURN server username')
    parser.add_argument('--password', help='TURN server password')
    parser.add_argument('--realm', help='TURN server authentication realm')
    parser.add_argument('--dns-server', default='8.8.8.8', help='DNS server IP address (default: 8.8.8.8)')
    parser.add_argument('--dns-port', type=int, default=53, help='DNS server port (default: 53)')
    parser.add_argument('--domain', default='www.example.com', help='Domain to query (default: www.example.com)')
    parser.add_argument('--refresh-interval', type=int, default=300, help='Refresh interval (seconds, default: 300)')
    parser.add_argument('--run-time', type=int, default=600, help='Run time (seconds, default: 600)')
    
    args = parser.parse_args()
    
    print("="*70)
    print("🔍 Simulating Normal TURN User Behavior")
    print("="*70)
    
    # Resolve TURN server address
    if args.turn_server:
        server_address = resolve_server_address(args.turn_server, args.turn_port or DEFAULT_TURN_PORT)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return
    else:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    print(f"[+] TURN Server: {server_address}")
    print(f"[+] DNS Server: {args.dns_server}:{args.dns_port}")
    print(f"[+] Domain: {args.domain}")
    print(f"[+] Refresh Interval: {args.refresh_interval} seconds")
    print(f"[+] Run Time: {args.run_time} seconds")
    print()
    
    # Start DNS query loop (create new allocation for each query)
    print("="*70)
    print("🔄 Starting DNS query loop (create new allocation for each query)...")
    print("="*70)
    
    start_time = time.time()
    query_count = 0
    
    try:
        while time.time() - start_time < args.run_time:
            query_count += 1
            print(f"\n[{time.strftime('%H:%M:%S')}] ========== DNS Query #{query_count} ==========")
            
            # 1. Allocate UDP TURN relay address (create new for each query)
            print(f"[1/4] Allocating UDP TURN relay address...")
            result, is_short_term = allocate_with_fallback(
                server_address,
                args.username,
                args.password,
                args.realm,
                args.turn_server,
            )
            
            if not result:
                print("[-] Failed to allocate TURN relay, skipping this query")
                time.sleep(5)
                continue
            
            sock, nonce, realm, integrity_key, actual_server_address, *extra = result
            mi_algorithm = extra[0] if extra else None
            
            print(f"[+] UDP TURN allocation successful")
            print(f"[+] Relay address: {actual_server_address}")
            
            # 2. Create permission to allow sending data to DNS server
            print(f"[2/4] Creating permission...")
            if not create_permission(sock, nonce, realm, integrity_key, 
                                   args.dns_server, args.dns_port, actual_server_address, args.username, mi_algorithm):
                print("[-] Failed to create permission, closing allocation")
                sock.close()
                time.sleep(5)
                continue
            print("[+] Permission created")
            
            # 3. Bind channel
            print(f"[3/4] Binding channel...")
            channel_number = 0x4000
            if not channel_bind(sock, nonce, realm, integrity_key, 
                               args.dns_server, args.dns_port, channel_number, actual_server_address, args.username, mi_algorithm):
                print("[-] Failed to bind channel, closing allocation")
                sock.close()
                time.sleep(5)
                continue
            print(f"[+] Channel {channel_number} bound successfully")
            
            # 4. Send DNS query and receive response
            print(f"[4/4] Sending DNS query and receiving response...")
            response = send_dns_query_and_receive(sock, channel_number, args.dns_server, args.dns_port, 
                                                  actual_server_address, args.domain)
            
            # Close allocation (close after each query)
            print(f"[+] Closing allocation...")
            sock.close()
            print(f"[+] DNS query #{query_count} completed\n")
            
            # Wait before sending next query
            time.sleep(10)
    
    except KeyboardInterrupt:
        print("\n[+] User interrupted")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[+] Completed")

if __name__ == "__main__":
    main()

