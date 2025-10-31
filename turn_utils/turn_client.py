"""
TURN客户端实现 - 支持UDP和TCP传输协议

本实现基于以下RFC规范：
- RFC 5766: TURN (Traversal Using Relays around NAT)
- RFC 6062: TURN Extensions for TCP Allocations

功能特性：
1. UDP TURN: 通过UDP通道发送数据
2. TCP TURN: 通过TCP连接发送数据（RFC 6062扩展）

使用方法：
- python turn_client.py          # 运行UDP演示
- python turn_client.py udp     # 运行UDP演示
- python turn_client.py tcp      # 运行基本TCP演示
- python turn_client.py tcp-full # 运行完整TCP演示（包含数据连接）
"""

import socket
import struct
import hmac
import hashlib
import random
import os
import sys
import zlib
import dns.resolver
import dns.exception
import time

# === 配置 ===
# 从配置文件导入TURN服务器配置
# 添加父目录到路径，以便导入config模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT, USERNAME, PASSWORD, REALM,
    DEFAULT_TIMEOUT, DEFAULT_CHANNEL_NUMBER
)

# STUN/TURN 常量
STUN_BINDING_REQUEST  = 0x0001
STUN_ALLOCATE_REQUEST = 0x0003
STUN_CREATE_PERMISSION_REQUEST = 0x0008
STUN_CHANNEL_BIND_REQUEST = 0x0009
# TCP TURN 扩展方法 (RFC 6062)
STUN_CONNECT_REQUEST = 0x000a
STUN_CONNECTION_BIND_REQUEST = 0x000b
STUN_CONNECTION_ATTEMPT_INDICATION = 0x000c
STUN_MAGIC_COOKIE     = 0x2112A442

# STUN 响应类型
STUN_ALLOCATE_SUCCESS_RESPONSE = 0x0103
STUN_ALLOCATE_ERROR_RESPONSE = 0x0113
STUN_CREATE_PERMISSION_SUCCESS_RESPONSE = 0x0108
STUN_CREATE_PERMISSION_ERROR_RESPONSE = 0x0118
STUN_CHANNEL_BIND_SUCCESS_RESPONSE = 0x0109
STUN_CHANNEL_BIND_ERROR_RESPONSE = 0x0119

# STUN 属性类型
STUN_ATTR_USERNAME = 0x0006
STUN_ATTR_MESSAGE_INTEGRITY = 0x0008
STUN_ATTR_REALM = 0x0014
STUN_ATTR_NONCE = 0x0015
STUN_ATTR_REQUESTED_TRANSPORT = 0x0019
STUN_ATTR_XOR_PEER_ADDRESS = 0x0012
STUN_ATTR_CHANNEL_NUMBER = 0x000C
STUN_ATTR_FINGERPRINT = 0x8028
STUN_ATTR_ERROR_CODE = 0x0009
STUN_ATTR_ALTERNATE_SERVER = 0x8023
# TCP TURN 扩展属性 (RFC 6062)
STUN_ATTR_CONNECTION_ID = 0x002a

def gen_tid():
    return os.urandom(12)

def is_ip_address(hostname):
    """检查输入是否为IP地址"""
    try:
        socket.inet_aton(hostname)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return True
        except socket.error:
            return False

def discover_turn_server_ips(hostname, max_queries=20):
    """发现TURN服务器的所有IP地址"""
    print(f"[+] Discovering all IPs for {hostname}")
    
    # 如果是IP地址，直接返回
    if is_ip_address(hostname):
        print(f"[+] Input is IP address: {hostname}")
        return [hostname]
    
    dns_servers = [
        '8.8.8.8', '8.8.4.4',      # Google DNS
        '1.1.1.1', '1.0.0.1',      # Cloudflare DNS
        '208.67.222.222', '208.67.220.220',  # OpenDNS
    ]
    
    discovered_ips = set()
    
    # 1. 系统DNS解析
    try:
        ip = socket.gethostbyname(hostname)
        discovered_ips.add(ip)
        print(f"[+] System DNS: {hostname} -> {ip}")
    except socket.gaierror as e:
        print(f"[-] System DNS failed: {e}")
    
    # 2. 多DNS服务器解析
    for i in range(max_queries):
        dns_server = random.choice(dns_servers)
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            answers = resolver.resolve(hostname, 'A')
            for answer in answers:
                ip = str(answer)
                if ip not in discovered_ips:
                    discovered_ips.add(ip)
                    print(f"[+] DNS query via {dns_server}: {hostname} -> {ip}")
            time.sleep(0.1)  # 避免DNS限制
        except dns.exception.DNSException:
            continue
    
    ip_list = list(discovered_ips)
    print(f"[+] Total discovered {len(ip_list)} IPs: {ip_list}")
    return ip_list

def resolve_server_address(server_host, server_port):
    """解析服务器地址，支持域名和IP地址"""
    try:
        # 尝试解析域名
        ip_address = socket.gethostbyname(server_host)
        print(f"[+] Resolved {server_host} to {ip_address}")
        return (ip_address, server_port)
    except socket.gaierror as e:
        print(f"[-] Failed to resolve {server_host}: {e}")
        return None

def resolve_peer_address(peer_host):
    """解析对等方地址，支持域名和IP地址"""
    try:
        # 尝试解析域名
        ip_address = socket.gethostbyname(peer_host)
        print(f"[+] Resolved peer {peer_host} to {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"[-] Failed to resolve peer {peer_host}: {e}")
        return None

def parse_alternate_server(attr_data):
    """解析ALTERNATE-SERVER属性"""
    if len(attr_data) < 8:
        return None
    
    # ALTERNATE-SERVER属性格式与MAPPED-ADDRESS相同（RFC8489第14.15节）
    # 格式: reserved(1) + family(1) + port(2) + address(4 for IPv4, 16 for IPv6)
    # 注意：不是XOR编码的，直接使用网络字节序
    
    # 尝试解析为未编码的地址
    if len(attr_data) == 8:  # IPv4
        # 第0字节是保留字段，必须为0
        reserved = attr_data[0]
        if reserved != 0:
            return None
            
        # 第1字节是地址族
        family = attr_data[1]
        if family == 1:  # IPv4
            # 端口是网络字节序，直接解析
            port = struct.unpack("!H", attr_data[2:4])[0]
            
            # IP地址是网络字节序，直接解析
            address = socket.inet_ntoa(attr_data[4:8])
            
            return (address, port)
    elif len(attr_data) == 20:  # IPv6
        # 第0字节是保留字段，必须为0
        reserved = attr_data[0]
        if reserved != 0:
            return None
            
        # 第1字节是地址族
        family = attr_data[1]
        if family == 2:  # IPv6
            # 端口是网络字节序，直接解析
            port = struct.unpack("!H", attr_data[2:4])[0]
            
            # IPv6地址是网络字节序，直接解析
            address = socket.inet_ntop(socket.AF_INET6, attr_data[4:20])
            
            return (address, port)
    
    return None

def stun_attr(attr_type, value):
    pad_len = (4 - (len(value) % 4)) % 4
    return struct.pack("!HH", attr_type, len(value)) + value + b"\x00" * pad_len

def build_msg(msg_type, tid, attrs, integrity_key=None, add_fingerprint=False):
    
    body = b"".join(attrs)
    
    if integrity_key:
        # 创建占位符HMAC
        mi_dummy = b"\x00" * 20
        mi_attr = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY, len(mi_dummy)) + mi_dummy
        body_with_mac_mi = body + mi_attr
        
        # 如果使用FINGERPRINT，先创建占位符FINGERPRINT
        fp_attr = None
        if add_fingerprint:
            fp_attr_mi = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, 0)  # 占位符FINGERPRINT
            body_with_mac_mi_and_fp_mi = body_with_mac_mi + fp_attr_mi
        
        # 生成header，长度包含FINGERPRINT（如果使用）
        header = struct.pack("!HHI12s", msg_type, len(body_with_mac_mi), STUN_MAGIC_COOKIE, tid)
        msg_for_hmac = header + body
        
        # 计算HMAC-SHA1
        hmac_val = hmac.new(integrity_key, msg_for_hmac, hashlib.sha1).digest()
        
        # 替换占位符为真实HMAC
        hmac_attr = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY, len(hmac_val)) + hmac_val
        body_with_hmac = body + hmac_attr
        header = struct.pack("!HHI12s", msg_type, len(body_with_hmac), STUN_MAGIC_COOKIE, tid)
        msg = header + body_with_hmac

        # 如果使用FINGERPRINT，重新添加占位符
        if add_fingerprint:
            body_with_hmac_and_fp_attr_mi = body_with_hmac + fp_attr_mi
        
            # 重新生成header，包含fingerprint dummy
            header = struct.pack("!HHI12s", msg_type, len(body_with_hmac_and_fp_attr_mi), STUN_MAGIC_COOKIE, tid)
            
        
        
            # 基于当前消息计算CRC32
            msg_for_crc = header + body_with_hmac # 但是 msg_for_crc 不包含FINGERPRINT
            crc32_val = zlib.crc32(msg_for_crc) & 0xffffffff
            #print(crc32_val.to_bytes(4).hex())
            fingerprint_val = crc32_val ^ 0x5354554e
            #print(fingerprint_val.to_bytes(4).hex())
            # 替换占位符FINGERPRINT为真实值
            fp_attr = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, fingerprint_val)
            
            # 重新构建消息
            body_with_hmac_and_fp = body + hmac_attr + fp_attr
            header = struct.pack("!HHI12s", msg_type, len(body_with_hmac_and_fp), STUN_MAGIC_COOKIE, tid)
            msg = header + body_with_hmac_and_fp
    else:
        msg = struct.pack("!HHI12s", msg_type, len(body), STUN_MAGIC_COOKIE, tid) + body

    return msg


def parse_attrs(data):
    attrs = {}
    msg_type, msg_len, magic, tid = struct.unpack("!HHI12s", data[:20])
    pos = 20
    while pos < 20 + msg_len:
        atype, alen = struct.unpack("!HH", data[pos:pos+4])
        aval = data[pos+4:pos+4+alen]
        attrs[atype] = aval
        pos += 4 + ((alen + 3) // 4) * 4
    return msg_type, tid, attrs

def allocate_single_server(server_address, username=None, password=None, realm=None):
    """向单个服务器分配UDP TURN中继地址"""
    # 使用传入的认证信息或默认值
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    try:
        # 1. 第一次 Allocate 请求（无认证）
        tid1 = gen_tid()
        req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))  # REQUESTED-TRANSPORT (UDP=17)
        ])
        sock.sendto(req1, server_address)
        data, _ = sock.recvfrom(2000)
        msg_type, tid, attrs = parse_attrs(data)
        print("[+] First resp attrs:", attrs)

        # 提取 nonce 和 realm
        nonce = attrs.get(STUN_ATTR_NONCE)   # NONCE
        server_realm = attrs.get(STUN_ATTR_REALM)   # REALM
        if not (nonce and server_realm):
            print("[-] No nonce/realm in response, exiting")
            sock.close()
            return None

        print(f"[+] Got nonce={nonce}, realm={server_realm}")

        # 2. 第二次 Allocate 请求
        tid2 = gen_tid()
        key_str = f"{auth_username}:{server_realm.decode()}:{auth_password}"
        print(f"[+] HMAC key string: {key_str}")
        integrity_key = hashlib.md5(key_str.encode()).digest()
        print(f"[+] HMAC key: {integrity_key.hex()}")

        attrs2 = [
            stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
            stun_attr(STUN_ATTR_REALM, server_realm),              # REALM
            stun_attr(STUN_ATTR_NONCE, nonce),              # NONCE
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT
        ]

        req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
        sock.sendto(req2, server_address)

        data, _ = sock.recvfrom(2000)
        msg_type, tid, attrs = parse_attrs(data)
        print("[+] Final resp attrs:", attrs)
        
        # 检查响应状态
        if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
            print("[+] UDP TURN allocation successful")
            return sock, nonce, server_realm, integrity_key
        elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            print("[-] UDP TURN allocation failed: Error response")
            # 检查错误码
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)  # ERROR-CODE attribute
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                error_reason = error_code[4:].decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                
                # 处理300 (Try Alternate)错误
                if error_class == 3 and error_number == 0:  # 300 Try Alternate
                    print("[+] Received Try Alternate error, checking for alternate server...")
                    alternate_server = attrs.get(STUN_ATTR_ALTERNATE_SERVER)
                    if alternate_server:
                        print(f"[+] Found ALTERNATE-SERVER attribute: {alternate_server.hex()}")
                        alt_addr = parse_alternate_server(alternate_server)
                        if alt_addr:
                            print(f"[+] Found alternate server: {alt_addr[0]}:{alt_addr[1]}")
                            sock.close()
                            # 递归调用使用备用服务器
                            return allocate_single_server(alt_addr, username, password, realm)
                        else:
                            print(f"[-] Failed to parse alternate server address: {alternate_server.hex()}")
                    else:
                        print("[+] No alternate server provided")
                        sock.close()
                        return None
            sock.close()
            return None
        else:
            print(f"[-] Unexpected response type: 0x{msg_type:04x}")
            sock.close()
            return None
            
    except Exception as e:
        print(f"[-] Allocation failed: {e}")
        sock.close()
        return None

def allocate_single_server_with_alternate(server_address, username=None, password=None, realm=None, tried_alternate_servers=None):
    """向单个服务器分配UDP TURN中继地址，支持ALTERNATE-SERVER重试"""
    if tried_alternate_servers is None:
        tried_alternate_servers = set()
    
    # 使用传入的认证信息或默认值
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    try:
        # 1. 第一次 Allocate 请求（无认证）
        tid1 = gen_tid()
        req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))  # REQUESTED-TRANSPORT (UDP=17)
        ])
        sock.sendto(req1, server_address)
        data, _ = sock.recvfrom(2000)
        msg_type, tid, attrs = parse_attrs(data)
        print("[+] First resp attrs:", attrs)

        # 提取 nonce 和 realm
        nonce = attrs.get(STUN_ATTR_NONCE)   # NONCE
        server_realm = attrs.get(STUN_ATTR_REALM)   # REALM
        if not (nonce and server_realm):
            print("[-] No nonce/realm in response, exiting")
            sock.close()
            return None

        print(f"[+] Got nonce={nonce}, realm={server_realm}")

        # 2. 第二次 Allocate 请求
        tid2 = gen_tid()
        key_str = f"{auth_username}:{server_realm.decode()}:{auth_password}"
        print(f"[+] HMAC key string: {key_str}")
        integrity_key = hashlib.md5(key_str.encode()).digest()
        print(f"[+] HMAC key: {integrity_key.hex()}")

        attrs2 = [
            stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
            stun_attr(STUN_ATTR_REALM, server_realm),              # REALM
            stun_attr(STUN_ATTR_NONCE, nonce),              # NONCE
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT
        ]

        req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
        sock.sendto(req2, server_address)

        data, _ = sock.recvfrom(2000)
        msg_type, tid, attrs = parse_attrs(data)
        print("[+] Final resp attrs:", attrs)
        
        # 检查响应状态
        if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
            print("[+] UDP TURN allocation successful")
            return sock, nonce, server_realm, integrity_key, server_address
        elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            print("[-] UDP TURN allocation failed: Error response")
            # 检查错误码
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)  # ERROR-CODE attribute
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                error_reason = error_code[4:].decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                
                # 处理300 (Try Alternate)错误
                if error_class == 3 and error_number == 0:  # 300 Try Alternate
                    print("[+] Received Try Alternate error, checking for alternate server...")
                    alternate_server = attrs.get(STUN_ATTR_ALTERNATE_SERVER)
                    if alternate_server:
                        print(f"[+] Found ALTERNATE-SERVER attribute: {alternate_server.hex()}")
                        alt_addr = parse_alternate_server(alternate_server)
                        if alt_addr:
                            alt_server_str = f"{alt_addr[0]}:{alt_addr[1]}"
                            print(f"[+] Found alternate server: {alt_server_str}")
                            
                            # 检查是否已经尝试过这个ALTERNATE-SERVER
                            if alt_server_str in tried_alternate_servers:
                                print(f"[+] ALTERNATE-SERVER {alt_server_str} already tried, skipping to avoid loop")
                                sock.close()
                                return None
                            
                            # 添加到已尝试列表
                            tried_alternate_servers.add(alt_server_str)
                            
                            sock.close()
                            print(f"[+] Recursively trying ALTERNATE-SERVER {alt_server_str}")
                            # 递归调用使用备用服务器
                            return allocate_single_server_with_alternate(alt_addr, username, password, realm, tried_alternate_servers)
                        else:
                            print(f"[-] Failed to parse alternate server address: {alternate_server.hex()}")
                    else:
                        print("[+] No alternate server provided")
                        sock.close()
                        return None
            sock.close()
            return None
        else:
            print(f"[-] Unexpected response type: 0x{msg_type:04x}")
            sock.close()
            return None
            
    except Exception as e:
        print(f"[-] Allocation failed: {e}")
        sock.close()
        return None

def allocate(server_address=None, username=None, password=None, realm=None, server_hostname=None):
    """分配UDP TURN中继地址，支持多IP备选和自动重试"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    # 获取服务器主机名用于DNS发现
    if server_hostname is None:
        server_hostname = server_address[0]
    
    # 发现所有IP地址
    server_ips = discover_turn_server_ips(server_hostname)
    server_port = server_address[1]
    
    print(f"[+] Trying {len(server_ips)} IP addresses for TURN server")
    
    # 用于跟踪已尝试的ALTERNATE-SERVER地址，避免无限循环
    tried_alternate_servers = set()
    
    # 尝试每个IP地址
    for i, ip in enumerate(server_ips):
        current_address = (ip, server_port)
        print(f"[+] Attempt {i+1}/{len(server_ips)}: Trying {current_address}")
        
        result = allocate_single_server_with_alternate(current_address, username, password, realm, tried_alternate_servers)
        if result:
            # result现在包含实际连接的服务器地址
            actual_connected_address = result[4] if len(result) > 4 else current_address
            print(f"[+] Successfully allocated on {actual_connected_address}")
            return result
        else:
            print(f"[-] Failed to allocate on {current_address}")
    
    print("[-] All UDP IP addresses failed")
    return None


def allocate_tcp_single_server(server_address, username=None, password=None, realm=None, use_tls=False):
    """向单个服务器分配TCP TURN中继地址（使用TCP传输）"""
    # 使用传入的认证信息或默认值
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
        
    # TCP TURN需要先建立TCP控制连接
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_sock.settimeout(10)
    
    try:
        # 连接到TURN服务器
        control_sock.connect(server_address)
        print(f"[+] Connected to TURN server {server_address}")
        
        # 如果使用TLS，建立SSL连接
        if use_tls:
            import ssl
            print("[+] Establishing TLS connection...")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            control_sock = context.wrap_socket(control_sock, server_hostname=server_address[0])
            print("[+] TLS connection established")
        
        # 1. 第一次 Allocate 请求（无认证）
        tid1 = gen_tid()
        req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00"))  # REQUESTED-TRANSPORT (TCP=6)
        ])
        control_sock.send(req1)
        
        # 接收响应
        data = control_sock.recv(2000)
        msg_type, tid, attrs = parse_attrs(data)
        print("[+] First TCP resp attrs:", attrs)

        # 提取 nonce 和 realm
        nonce = attrs.get(STUN_ATTR_NONCE)   # NONCE
        server_realm = attrs.get(STUN_ATTR_REALM)   # REALM
        if not (nonce and server_realm):
            print("[-] No nonce/realm in response, exiting")
            return

        print(f"[+] Got nonce={nonce}, realm={server_realm}")

        # 2. 第二次 Allocate 请求
        tid2 = gen_tid()
        key_str = f"{auth_username}:{server_realm.decode()}:{auth_password}"
        integrity_key = hashlib.md5(key_str.encode()).digest()

        attrs2 = [
            stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
            stun_attr(STUN_ATTR_REALM, server_realm),              # REALM
            stun_attr(STUN_ATTR_NONCE, nonce),              # NONCE
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT (TCP=6, RFC6062规定TCP使用TCP传输)
        ]

        req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
        control_sock.send(req2)

        data = control_sock.recv(2000)
        msg_type, tid, attrs = parse_attrs(data)
        print("[+] Final TCP resp attrs:", attrs)
        
        # 检查响应状态
        if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
            print("[+] TCP TURN allocation successful")
            return control_sock, nonce, server_realm, integrity_key, server_address
        elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            print("[-] TCP TURN allocation failed: Error response")
            # 检查错误码
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)  # ERROR-CODE attribute
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                error_reason = error_code[4:].decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                
                # 处理300 (Try Alternate)错误
                if error_class == 3 and error_number == 0:  # 300 Try Alternate
                    print("[+] Received Try Alternate error, checking for alternate server...")
                    alternate_server = attrs.get(STUN_ATTR_ALTERNATE_SERVER)
                    if alternate_server:
                        alt_addr = parse_alternate_server(alternate_server)
                        if alt_addr:
                            print(f"[+] Found alternate server: {alt_addr[0]}:{alt_addr[1]}")
                            control_sock.close()
                            # 递归调用使用备用服务器
                            return allocate_tcp_single_server(alt_addr, username, password, realm, use_tls)
                        else:
                            print("[-] Failed to parse alternate server address")
                    else:
                        print("[+] No alternate server provided")
                        control_sock.close()
                        return None
            control_sock.close()
            return None
        else:
            print(f"[-] Unexpected response type: 0x{msg_type:04x}")
            control_sock.close()
            return None
        
    except Exception as e:
        print(f"[-] TCP allocation failed: {e}")
        control_sock.close()
        return None

def allocate_tcp_udp(server_address=None, username=None, password=None, realm=None, use_tls=False, server_hostname=None):
    """分配TCP连接但UDP中继的TURN地址，支持多IP备选和自动重试"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    # 如果提供了主机名，先进行DNS解析
    if server_hostname:
        print(f"[+] Discovering all IPs for {server_hostname}")
        ips = discover_turn_server_ips(server_hostname)
        if ips:
            print(f"[+] Total discovered {len(ips)} IPs: {ips}")
            print(f"[+] Trying {len(ips)} IP addresses for TCP+UDP TURN server")
        else:
            print(f"[-] Failed to discover IPs for {server_hostname}")
            return None
    else:
        # 直接使用提供的IP地址
        ips = [server_address[0]]
    
    # 尝试每个IP地址
    for i, ip in enumerate(ips, 1):
        current_address = (ip, server_address[1])
        print(f"[+] TCP+UDP Attempt {i}/{len(ips)}: Trying {current_address}")
        
        result = allocate_tcp_udp_single_server(current_address, username, password, realm, use_tls, server_hostname)
        if result:
            print(f"[+] Successfully allocated TCP+UDP on {current_address}")
            return result
        else:
            print(f"[-] Failed to allocate TCP+UDP on {current_address}")
    
    print("[-] All TCP+UDP IP addresses failed")
    return None

def allocate_tcp_udp_single_server(server_address, username=None, password=None, realm=None, use_tls=False, server_hostname=None):
    """向单个服务器分配TCP连接但UDP中继的TURN地址"""
    # 使用传入的认证信息或默认值
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
        
    # TCP TURN需要先建立TCP控制连接
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_sock.settimeout(10)
    
    try:
        # 连接到TURN服务器
        control_sock.connect(server_address)
        print(f"[+] Connected to TURN server {server_address}")
        
        # 如果使用TLS，建立SSL连接
        if use_tls:
            import ssl
            print("[+] Establishing TLS connection...")
            context = ssl.create_default_context()
            # 使用主机名而不是IP地址进行SSL握手
            ssl_hostname = server_hostname or server_address[0]
            control_sock = context.wrap_socket(control_sock, server_hostname=ssl_hostname)
            print("[+] TLS connection established")
        
        # 第一次分配请求（无认证）
        tid1 = gen_tid()
        attrs1 = [
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT (UDP=17)
        ]
        
        req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, attrs1, None, add_fingerprint=False)
        control_sock.send(req1)
        
        # 接收第一次响应
        data = control_sock.recv(2000)
        msg_type, tid, attrs = parse_attrs(data)
        print("[+] First TCP+UDP resp attrs:", attrs)
        
        # 检查响应类型
        if msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            # 检查错误代码
            error_code = attrs.get(9)
            # 检查是否是401 Unauthorized错误
            is_unauthorized = False
            if error_code:
                # 检查错误代码格式: 前2字节是错误类，第3字节是错误号
                if len(error_code) >= 4:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    if error_class == 4 and error_number == 1:  # 401 Unauthorized
                        is_unauthorized = True
                # 也检查文本形式的错误
                if b"Unauthorized" in error_code or b"401" in error_code:
                    is_unauthorized = True
            
            if is_unauthorized:
                print("[+] Got nonce and realm for authentication")
                nonce = attrs.get(21)
                server_realm = attrs.get(20)
                
                if nonce and server_realm:
                    print(f"[+] Got nonce={nonce}, realm={server_realm}")
                    
                    # 计算完整性密钥
                    key_str = f"{auth_username}:{server_realm.decode()}:{auth_password}"
                    print(f"[+] HMAC key string: {key_str}")
                    integrity_key = hashlib.md5(key_str.encode()).digest()
                    print(f"[+] HMAC key: {integrity_key.hex()}")
                    
                    # 第二次分配请求（带认证）
                    tid2 = gen_tid()
                    attrs2 = [
                        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
                        stun_attr(STUN_ATTR_REALM, server_realm),              # REALM
                        stun_attr(STUN_ATTR_NONCE, nonce),              # NONCE
                        stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT (UDP=17)
                    ]

                    req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
                    control_sock.send(req2)
                    
                    # 接收第二次响应
                    data = control_sock.recv(2000)
                    msg_type, tid, attrs = parse_attrs(data)
                    print("[+] Final TCP+UDP resp attrs:", attrs)
                    
                    # 检查是否成功
                    if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                        print("[+] TCP+UDP TURN allocation successful")
                        return control_sock, nonce, server_realm, integrity_key, server_address
                    elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                        error_code = attrs.get(9)
                        if error_code:
                            # 解析错误代码
                            if len(error_code) >= 4:
                                error_class = error_code[2]
                                error_number = error_code[3]
                                error_text = error_code[4:].decode('utf-8', errors='ignore')
                                print(f"[-] TCP+UDP TURN allocation failed: Error response")
                                print(f"[-] Error: {error_class}{error_number:02d} {error_text}")
                            else:
                                error_text = error_code[3:].decode('utf-8', errors='ignore')
                                print(f"[-] TCP+UDP TURN allocation failed: Error response")
                                print(f"[-] Error: {error_text}")
                        control_sock.close()
                        return None
                    else:
                        print(f"[-] Unexpected response type: 0x{msg_type:04x}")
                        control_sock.close()
                        return None
                else:
                    print("[-] Missing nonce or realm in response")
                    control_sock.close()
                    return None
            elif error_code and b"Try Alternate" in error_code:
                print("[+] Got Try Alternate response")
                # 解析ALTERNATE-SERVER属性
                alt_server = attrs.get(0x8023)  # ALTERNATE-SERVER
                if alt_server:
                    alt_addr = parse_alternate_server(alt_server)
                    if alt_addr:
                        print(f"[+] Trying alternate server: {alt_addr}")
                        control_sock.close()
                        # 递归尝试备用服务器
                        return allocate_tcp_udp_single_server(alt_addr, username, password, realm, use_tls, server_hostname)
                    else:
                        print("[-] Failed to parse alternate server address")
                else:
                    print("[+] No alternate server provided")
                    control_sock.close()
                    return None
            else:
                print("[-] Unexpected error response")
                control_sock.close()
                return None
        else:
            print(f"[-] Unexpected response type: 0x{msg_type:04x}")
            control_sock.close()
            return None
        
    except Exception as e:
        print(f"[-] TCP+UDP allocation failed: {e}")
        control_sock.close()
        return None


def allocate_tcp(server_address=None, username=None, password=None, realm=None, use_tls=False, server_hostname=None):
    """分配TCP TURN中继地址，支持多IP备选和自动重试"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    # 获取服务器主机名用于DNS发现
    if server_hostname is None:
        server_hostname = server_address[0]
    
    # 发现所有IP地址
    server_ips = discover_turn_server_ips(server_hostname)
    server_port = server_address[1]
    
    print(f"[+] Trying {len(server_ips)} IP addresses for TCP TURN server")
    
    # 尝试每个IP地址
    for i, ip in enumerate(server_ips):
        current_address = (ip, server_port)
        print(f"[+] TCP Attempt {i+1}/{len(server_ips)}: Trying {current_address}")
        
        result = allocate_tcp_single_server(current_address, username, password, realm, use_tls)
        if result:
            print(f"[+] Successfully allocated TCP on {current_address}")
            return result
        else:
            print(f"[-] Failed to allocate TCP on {current_address}")
    
    print("[-] All TCP IP addresses failed")
    return None

def create_permission(sock, nonce, realm, integrity_key, peer_ip, peer_port, server_address=None, username=None):
    """创建权限，允许向指定对等方发送数据"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Creating permission for {peer_ip}:{peer_port}")
    
    # 解析对等方地址（支持域名）
    resolved_peer_ip = resolve_peer_address(peer_ip)
    if not resolved_peer_ip:
        print(f"[-] Failed to resolve peer address {peer_ip}")
        return False
    
    # 将IP地址转换为网络字节序
    peer_addr = socket.inet_aton(resolved_peer_ip)
    # XOR编码地址（使用magic cookie）
    xor_port = peer_port ^ (STUN_MAGIC_COOKIE >> 16)
    xor_addr = struct.pack("!BBH", 0, 1, xor_port) + peer_addr  # IPv4, XOR端口，IP地址
    
    # XOR编码IP地址
    xor_ip = bytes([peer_addr[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)])
    xor_addr = struct.pack("!BBH", 0, 1, xor_port) + xor_ip
    
    # 使用传入的用户名或默认用户名
    auth_username = username or USERNAME
    
    tid = gen_tid()
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
        stun_attr(STUN_ATTR_REALM, realm),
        stun_attr(STUN_ATTR_NONCE, nonce),
        stun_attr(STUN_ATTR_XOR_PEER_ADDRESS, xor_addr),
    ]
    
    req = build_msg(STUN_CREATE_PERMISSION_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    
    # 检查是否为SSL套接字（更准确的检测方法）
    if hasattr(sock, '_sslobj') or sock.__class__.__name__ == 'SSLSocket':
        # SSL/TLS套接字
        sock.send(req)
        data = sock.recv(2000)
    else:
        # UDP套接字
        sock.sendto(req, server_address)
        data, _ = sock.recvfrom(2000)
    
    msg_type, tid, attrs = parse_attrs(data)
    print("[+] CreatePermission response:", attrs)
    
    # 检查是否有错误响应
    if msg_type == STUN_CREATE_PERMISSION_ERROR_RESPONSE:
        error_code = attrs.get(9)  # STUN_ATTR_ERROR_CODE
        if error_code:
            error_code_int = struct.unpack("!H", error_code[:2])[0]
            error_reason = error_code[4:].decode('utf-8', errors='ignore')
            print(f"[-] CreatePermission failed: {error_code_int} {error_reason}")
            return False
    
    return True

def channel_bind(sock, nonce, realm, integrity_key, peer_ip, peer_port, channel_number, server_address=None, username=None):
    """绑定通道号到对等方地址"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Binding channel {channel_number} to {peer_ip}:{peer_port}")
    
    # 解析对等方地址（支持域名）
    resolved_peer_ip = resolve_peer_address(peer_ip)
    if not resolved_peer_ip:
        print(f"[-] Failed to resolve peer address {peer_ip}")
        return False
    
    # 将IP地址转换为网络字节序
    peer_addr = socket.inet_aton(resolved_peer_ip)
    # XOR编码地址（使用magic cookie）
    xor_port = peer_port ^ (STUN_MAGIC_COOKIE >> 16)
    
    # XOR编码IP地址
    xor_ip = bytes([peer_addr[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)])
    xor_addr = struct.pack("!BBH", 0, 1, xor_port) + xor_ip
    
    # 使用传入的用户名或默认用户名
    auth_username = username or USERNAME
    
    tid = gen_tid()
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
        stun_attr(STUN_ATTR_REALM, realm),
        stun_attr(STUN_ATTR_NONCE, nonce),
        stun_attr(STUN_ATTR_CHANNEL_NUMBER, struct.pack("!HH", channel_number, 0)),
        stun_attr(STUN_ATTR_XOR_PEER_ADDRESS, xor_addr),
    ]
    
    req = build_msg(STUN_CHANNEL_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    
    # 检查是否为SSL套接字（更准确的检测方法）
    if hasattr(sock, '_sslobj') or sock.__class__.__name__ == 'SSLSocket':
        # SSL/TLS套接字
        sock.send(req)
        data = sock.recv(2000)
    else:
        # UDP套接字
        sock.sendto(req, server_address)
        data, _ = sock.recvfrom(2000)
    
    msg_type, tid, attrs = parse_attrs(data)
    print("[+] ChannelBind response:", attrs)
    
    # 检查是否有错误响应
    if msg_type == STUN_CHANNEL_BIND_ERROR_RESPONSE:
        error_code = attrs.get(9)  # STUN_ATTR_ERROR_CODE
        if error_code:
            error_code_int = struct.unpack("!H", error_code[:2])[0]
            error_reason = error_code[4:].decode('utf-8', errors='ignore')
            print(f"[-] ChannelBind failed: {error_code_int} {error_reason}")
            return False
    
    return True

def channel_data_tcp(control_sock, channel_number, data, server_address=None):
    """通过TCP控制连接发送ChannelData消息"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Sending data through channel {channel_number}: {data}")
    
    # ChannelData消息格式：通道号(2字节) + 数据长度(2字节) + 数据
    channel_data_msg = struct.pack("!HH", channel_number, len(data)) + data
    
    try:
        control_sock.send(channel_data_msg)
        print("[+] ChannelData sent successfully")
        return True
    except Exception as e:
        print(f"[-] Failed to send ChannelData: {e}")
        return False

def channel_data(sock, channel_number, data, server_address=None):
    """通过通道发送数据"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Sending data through channel {channel_number}: {data}")
    
    # ChannelData消息格式：通道号(2字节) + 数据长度(2字节) + 数据
    channel_data_msg = struct.pack("!HH", channel_number, len(data)) + data
    
    sock.sendto(channel_data_msg, server_address)
    print("[+] ChannelData sent successfully")
    
    return True

def tcp_connect(control_sock, nonce, realm, integrity_key, peer_ip, peer_port, username=None):
    """发起TCP连接到对等方 (RFC 6062 Connect请求)"""
    print(f"[+] Initiating TCP connection to {peer_ip}:{peer_port}")
    
    # 解析对等方地址（支持域名）
    resolved_peer_ip = resolve_peer_address(peer_ip)
    if not resolved_peer_ip:
        print(f"[-] Failed to resolve peer address {peer_ip}")
        return None
    
    # 将IP地址转换为网络字节序
    peer_addr = socket.inet_aton(resolved_peer_ip)
    # XOR编码地址（使用magic cookie）
    xor_port = peer_port ^ (STUN_MAGIC_COOKIE >> 16)
    
    # XOR编码IP地址
    xor_ip = bytes([peer_addr[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)])
    xor_addr = struct.pack("!BBH", 0, 1, xor_port) + xor_ip
    
    tid = gen_tid()
    # 使用传入的用户名或默认值
    auth_username = username or USERNAME
    print(f"[+] Using username for Connect request: {auth_username}")
    
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
        stun_attr(STUN_ATTR_REALM, realm),
        stun_attr(STUN_ATTR_NONCE, nonce),
        stun_attr(STUN_ATTR_XOR_PEER_ADDRESS, xor_addr),
    ]
    
    req = build_msg(STUN_CONNECT_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    control_sock.send(req)
    
    # 接收Connect响应
    data = control_sock.recv(2000)
    msg_type, tid, attrs = parse_attrs(data)
    print("[+] Connect response:", attrs)
    
    # 检查响应类型
    if msg_type == 0x010a:  # Connect Success Response (0x010a)
        print("[+] Connect successful")
        connection_id = attrs.get(STUN_ATTR_CONNECTION_ID)
        if connection_id:
            conn_id = struct.unpack("!I", connection_id)[0]
            print(f"[+] Got connection ID: {conn_id}")
            return conn_id
        else:
            print("[-] No connection ID in Connect response")
            print("[-] Response attributes keys:", list(attrs.keys()))
            return None
    elif msg_type == 0x011a:  # Connect Error Response (0x011a)
        print("[-] Connect error")
        error_code = attrs.get(STUN_ATTR_ERROR_CODE)
        if error_code:
            if len(error_code) >= 4:
                error_class = error_code[2]
                error_number = error_code[3]
                error_text = error_code[4:].decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_class}{error_number:02d} {error_text}")
            else:
                error_text = error_code.decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_text}")
        print("[-] Response attributes keys:", list(attrs.keys()))
        return None
    else:
        print(f"[-] Unexpected response type: 0x{msg_type:04x}")
        print("[-] Response attributes keys:", list(attrs.keys()))
        return None

def tcp_connection_bind(control_sock, nonce, realm, integrity_key, connection_id, server_address=None, username=None):
    """绑定客户端数据连接到对等方连接 (RFC 6062 ConnectionBind请求)"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Binding data connection with connection ID {connection_id}")
    
    # 使用传入的用户名或默认值
    auth_username = username or USERNAME
    
    tid = gen_tid()
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
        stun_attr(STUN_ATTR_REALM, realm),
        stun_attr(STUN_ATTR_NONCE, nonce),
        stun_attr(STUN_ATTR_CONNECTION_ID, struct.pack("!I", connection_id)),
    ]
    
    req = build_msg(STUN_CONNECTION_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    control_sock.send(req)
    
    # 接收ConnectionBind响应
    data = control_sock.recv(2000)
    msg_type, tid, attrs = parse_attrs(data)
    print("[+] ConnectionBind response:", attrs)
    
    return True

def tcp_send_data(data_sock, data):
    """通过TCP数据连接发送数据"""
    print(f"[+] Sending TCP data: {data}")
    try:
        data_sock.send(data)
        print("[+] TCP data sent successfully")
        return True
    except Exception as e:
        print(f"[-] Failed to send TCP data: {e}")
        return False

def tcp_receive_data(data_sock, buffer_size=1024):
    """从TCP数据连接接收数据"""
    try:
        data = data_sock.recv(buffer_size)
        if data:
            print(f"[+] Received TCP data: {data}")
            return data
        else:
            print("[+] TCP connection closed by peer")
            return None
    except Exception as e:
        print(f"[-] Failed to receive TCP data: {e}")
        return None

def main(target_ip, target_port, turn_server=None, turn_port=None, username=None, password=None, realm=None):
    """主函数：演示UDP TURN客户端功能"""
    print("[+] Starting UDP TURN client...")
    
    # 解析TURN服务器地址
    if turn_server:
        server_address = resolve_server_address(turn_server, turn_port or DEFAULT_TURN_PORT)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return
    else:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    print(f"[+] Using TURN server: {server_address}")
    
    # 1. 分配TURN中继地址
    result = allocate(server_address, username, password, realm, turn_server)
    if not result:
        print("[-] Failed to allocate TURN relay")
        return
    
    sock, nonce, realm, integrity_key, actual_server_address = result
    print("[+] TURN allocation successful")
    
    # 2. 配置目标对等方
    import random
    channel_number = random.randint(0x4000, 0x4FFF)  # 随机生成通道号（必须在0x4000-0x4FFF范围内）
    
    # 3. 创建权限（使用实际连接的服务器地址和正确的用户名）
    if not create_permission(sock, nonce, realm, integrity_key, target_ip, target_port, actual_server_address, username):
        print("[-] Failed to create permission")
        return
    
    # 4. 绑定通道（使用实际连接的服务器地址和正确的用户名）
    if not channel_bind(sock, nonce, realm, integrity_key, target_ip, target_port, channel_number, actual_server_address, username):
        print("[-] Failed to bind channel")
        return
    
    # 5. 通过通道发送数据
    test_data = b"Hello from UDP TURN client!"
    if not channel_data(sock, channel_number, test_data, actual_server_address):
        print("[-] Failed to send channel data")
        return
    
    print("[+] UDP TURN client demo completed successfully")
    
    # 关闭socket
    sock.close()

def main_tcp_udp(target_ip, target_port, turn_server=None, turn_port=None, username=None, password=None, realm=None, use_tls=False):
    """TCP连接 + UDP中继的TURN客户端演示"""
    print("=== Running TCP+UDP TURN Demo ===")
    print(f"Target: {target_ip}:{target_port}")
    if turn_server:
        print(f"TURN Server: {turn_server}:{turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    
    print("[+] Starting TCP+UDP TURN client...")
    
    # 确定服务器地址
    if turn_server:
        server_address = (turn_server, turn_port or DEFAULT_TURN_PORT)
    else:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    # 1. 分配TCP TURN中继地址（但使用UDP中继）
    result = allocate_tcp_udp(server_address, username, password, realm, use_tls, turn_server)
    if not result:
        print("[-] Failed to allocate TCP+UDP TURN relay")
        return
    
    control_sock, nonce, realm, integrity_key, actual_server_address = result
    print("[+] TCP+UDP TURN allocation successful")
    
    # 2. 创建权限
    if not create_permission(control_sock, nonce, realm, integrity_key, target_ip, target_port, actual_server_address, username):
        print("[-] Failed to create permission")
        control_sock.close()
        return
    
    # 3. 绑定通道
    import random
    channel_number = random.randint(0x4000, 0x4FFF)
    if not channel_bind(control_sock, nonce, realm, integrity_key, target_ip, target_port, channel_number, actual_server_address, username):
        print("[-] Failed to bind channel")
        control_sock.close()
        return
    
    # 4. 通过通道发送数据
    test_data = b'Hello from TCP+UDP TURN client!'
    if not channel_data_tcp(control_sock, channel_number, test_data, actual_server_address):
        print("[-] Failed to send channel data")
        control_sock.close()
        return
    
    print("[+] TCP+UDP TURN client demo completed successfully")
    control_sock.close()


def main_tcp(target_ip, target_port, turn_server=None, turn_port=None, username=None, password=None, realm=None, use_tls=False):
    """主函数：演示TCP TURN客户端功能"""
    print("[+] Starting TCP TURN client...")
    
    # 解析TURN服务器地址
    if turn_server:
        server_address = resolve_server_address(turn_server, turn_port or DEFAULT_TURN_PORT)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return
    else:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    print(f"[+] Using TURN server: {server_address}")
    
    # 1. 分配TCP TURN中继地址
    result = allocate_tcp(server_address, username, password, realm, use_tls, turn_server)
    if not result:
        print("[-] Failed to allocate TCP TURN relay")
        return
    
    control_sock, nonce, realm, integrity_key, actual_server_address = result
    print("[+] TCP TURN allocation successful")
    
    # 3. 发起TCP连接到对等方
    connection_id = tcp_connect(control_sock, nonce, realm, integrity_key, target_ip, target_port, username)
    if not connection_id:
        print("[-] Failed to initiate TCP connection")
        control_sock.close()
        return
    
    # 4. 建立数据连接（RFC6062要求）
    print("[+] Establishing data connection to TURN server...")
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_sock.settimeout(10)
    
    try:
        # 建立新的TCP连接到TURN服务器作为数据连接
        data_sock.connect(actual_server_address)
        print(f"[+] Data connection established to {actual_server_address}")
        
        # 在数据连接上发送ConnectionBind请求
        if not tcp_connection_bind(data_sock, nonce, realm, integrity_key, connection_id, actual_server_address, username):
            print("[-] Failed to bind data connection")
            data_sock.close()
            control_sock.close()
            return
        
        print("[+] Data connection bound successfully")
        
        # 5. 发送测试数据
        test_data = b"Hello from TCP TURN client!"
        print(f"[+] Sending TCP data: {test_data}")
        data_sock.send(test_data)
        
        # 6. 接收响应数据
        print("[+] Waiting for response...")
        try:
            response = data_sock.recv(1024)
            if response:
                print(f"[+] Received response: {response}")
            else:
                print("[+] Connection closed by peer")
        except socket.timeout:
            print("[+] No response received (timeout)")
        
        print("[+] TCP TURN client demo completed successfully")
        
    except Exception as e:
        print(f"[-] Failed to establish data connection: {e}")
    finally:
        # 关闭连接
        data_sock.close()
        control_sock.close()

    

def test():
    
    tid2 = bytes.fromhex("53596a9f080f78580957e6d3")
    key_str = f"demo:anjhz3.com:demoPass123"
    integrity_key = hashlib.md5(key_str.encode()).digest()

    attrs2 = [
        stun_attr(STUN_ATTR_USERNAME, USERNAME.encode()),   # USERNAME
        stun_attr(STUN_ATTR_REALM, b"anjhz3.com"),              # REALM
        stun_attr(STUN_ATTR_NONCE, b'c4a0ab8162347fad'),              # NONCE
        stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT
    ]

    req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)

    
    
if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='TURN客户端实现 - 支持UDP和TCP传输协议')
    parser.add_argument('mode', nargs='?', choices=['udp', 'tcp-udp', 'tcp'], default='udp',
                       help='运行模式: udp (UDP TURN), tcp-udp (TCP连接+UDP中继), tcp (TCP TURN)')
    parser.add_argument('--target-ip', required=True, help='目标IP地址')
    parser.add_argument('--target-port', type=int, required=True, help='目标端口')
    parser.add_argument('--turn-server', help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    parser.add_argument('--username', help='TURN服务器用户名')
    parser.add_argument('--password', help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    parser.add_argument('--tls', action='store_true', help='使用TLS加密连接')
    
    args = parser.parse_args()
    
    print(f"=== Running {args.mode.upper()} TURN Demo ===")
    print(f"Target: {args.target_ip}:{args.target_port}")
    if args.turn_server:
        print(f"TURN Server: {args.turn_server}:{args.turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    
    if args.mode == "udp":
        main(args.target_ip, args.target_port, args.turn_server, args.turn_port, args.username, args.password, args.realm)
    elif args.mode == "tcp-udp":
        main_tcp_udp(args.target_ip, args.target_port, args.turn_server, args.turn_port, args.username, args.password, args.realm, args.tls)
    elif args.mode == "tcp":
        main_tcp(args.target_ip, args.target_port, args.turn_server, args.turn_port, args.username, args.password, args.realm, args.tls)
    
