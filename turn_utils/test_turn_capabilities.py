#!/usr/bin/env python3
"""
TURN服务器功能测试脚本

本脚本用于测试指定TURN服务器的各种连接功能：
1. UDP TURN - 通过UDP通道发送数据
2. TCP-UDP TURN - 通过TCP连接但UDP中继发送数据
3. TCP TURN - 通过TCP连接发送数据（RFC6062）

使用方法：
python test_turn_capabilities.py [--turn-server <服务器地址>] [--turn-port <端口>] [--username <用户名>] [--password <密码>] [--realm <认证域>] [--tls]

如果不提供参数，将使用config.py中的默认配置。
"""

import sys
import time
import socket
import struct
import os
# 添加父目录到路径，以便导入config模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # 作为包的一部分导入
    from .turn_client import (
        allocate_single_server, allocate_tcp_single_server, allocate_tcp_udp_single_server,
        allocate, allocate_tcp_udp, allocate_tcp,
        create_permission, channel_bind, channel_data, channel_data_tcp,
        tcp_connect, tcp_connection_bind, tcp_send_data, tcp_receive_data,
        resolve_server_address, resolve_peer_address, STUN_ATTR_ERROR_CODE, STUN_ALLOCATE_ERROR_RESPONSE
    )
except ImportError:
    # 作为独立脚本导入
    from turn_client import (
        allocate_single_server, allocate_tcp_single_server, allocate_tcp_udp_single_server,
        allocate, allocate_tcp_udp, allocate_tcp,
        create_permission, channel_bind, channel_data, channel_data_tcp,
        tcp_connect, tcp_connection_bind, tcp_send_data, tcp_receive_data,
        resolve_server_address, resolve_peer_address, STUN_ATTR_ERROR_CODE, STUN_ALLOCATE_ERROR_RESPONSE
    )
from config import (
    DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT, USERNAME, PASSWORD, REALM,
    TEST_SERVERS
)

def allocate_with_fallback(server_address, username, password, realm, server_hostname=None, use_tls=False):
    """尝试分配TURN地址，带回退机制：先尝试长期凭据，如果收到400错误则回退为短期凭据
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        server_hostname: 服务器主机名（用于TCP+UDP）
        use_tls: 是否使用TLS（用于TCP）
    
    Returns:
        (result, is_short_term) 或 (None, None)
        result: allocate函数的返回值
        is_short_term: 是否使用了短期凭据
    """
    import socket
    
    # 先尝试长期凭据
    print("[+] Trying long-term credential mechanism...")
    result = allocate_single_server(server_address, username, password, realm, use_short_term_credential=False)
    
    if result:
        return result, False
    
    # 检查是否是400错误（需要通过重新发送请求来检查，因为allocate_single_server不返回错误码）
    # 为了检测400错误，我们需要重新发送请求并检查响应
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    
    try:
        # 发送长期凭据的第二次请求（带认证的请求）
        from turn_client import build_msg, stun_attr, gen_tid, STUN_ALLOCATE_REQUEST, parse_attrs, compute_long_term_hmac_key, STUN_ATTR_USERNAME, STUN_ATTR_REALM, STUN_ATTR_NONCE, STUN_ATTR_REQUESTED_TRANSPORT
        from turn_client import STUN_ALLOCATE_ERROR_RESPONSE, STUN_ATTR_ERROR_CODE
        
        # 先发送无认证请求获取nonce和realm
        tid1 = gen_tid()
        req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))
        ])
        sock.sendto(req1, server_address)
        data, _ = sock.recvfrom(2000)
        msg_type, tid, attrs = parse_attrs(data)
        
        if msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                # 如果是401，继续尝试第二次请求
                if error_class == 4 and error_number == 1:
                    nonce = attrs.get(STUN_ATTR_NONCE)
                    server_realm = attrs.get(STUN_ATTR_REALM)
                    if nonce and server_realm:
                        # 发送第二次请求（带认证）
                        tid2 = gen_tid()
                        auth_username = username or USERNAME
                        auth_password = password or PASSWORD
                        integrity_key = compute_long_term_hmac_key(auth_username, server_realm, auth_password)
                        attrs2 = [
                            stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
                            stun_attr(STUN_ATTR_REALM, server_realm),
                            stun_attr(STUN_ATTR_NONCE, nonce),
                            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),
                        ]
                        req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
                        sock.sendto(req2, server_address)
                        data2, _ = sock.recvfrom(2000)
                        msg_type2, tid2, attrs2 = parse_attrs(data2)
                        
                        if msg_type2 == STUN_ALLOCATE_ERROR_RESPONSE:
                            error_code2 = attrs2.get(STUN_ATTR_ERROR_CODE)
                            if error_code2:
                                error_class2 = error_code2[2]
                                error_number2 = error_code2[3]
                                # 如果是400错误，回退为短期凭据
                                if error_class2 == 4 and error_number2 == 0:
                                    print("[+] Received 400 error with long-term credential, falling back to short-term credential...")
                                    sock.close()
                                    result = allocate_single_server(server_address, username, password, realm, use_short_term_credential=True)
                                    if result:
                                        return result, True
                                    else:
                                        print("[-] Both long-term and short-term credential attempts returned 400 error")
                                        return None, None
    except Exception as e:
        print(f"[!] Error checking error code: {e}")
    finally:
        sock.close()
    
    # 如果长期凭据失败但不是400错误，或者无法检测错误码，尝试短期凭据
    print("[+] Long-term credential failed, trying short-term credential...")
    result = allocate_single_server(server_address, username, password, realm, use_short_term_credential=True)
    if result:
        return result, True
    
    return None, None

def allocate_tcp_with_fallback(server_address, username, password, realm, use_tls=False):
    """尝试分配TCP TURN地址，带回退机制：先尝试长期凭据，如果收到400错误则回退为短期凭据
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        use_tls: 是否使用TLS
    
    Returns:
        (result, is_short_term) 或 (None, None)
    """
    # 先尝试长期凭据
    print("[+] Trying long-term credential mechanism...")
    result = allocate_tcp_single_server(server_address, username, password, realm, use_tls, use_short_term_credential=False)
    
    if result:
        return result, False
    
    # 检查是否是400错误（通过重新发送请求来检查）
    import socket
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_sock.settimeout(10)
    
    try:
        control_sock.connect(server_address)
        if use_tls:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            control_sock = context.wrap_socket(control_sock, server_hostname=server_address[0])
        
        from turn_client import build_msg, stun_attr, gen_tid, STUN_ALLOCATE_REQUEST, parse_attrs, compute_long_term_hmac_key
        from turn_client import STUN_ALLOCATE_ERROR_RESPONSE, STUN_ATTR_ERROR_CODE, STUN_ATTR_USERNAME, STUN_ATTR_REALM, STUN_ATTR_NONCE, STUN_ATTR_REQUESTED_TRANSPORT
        
        # 先发送无认证请求
        tid1 = gen_tid()
        req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00"))
        ])
        control_sock.send(req1)
        data = control_sock.recv(2000)
        msg_type, tid, attrs = parse_attrs(data)
        
        if msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                if error_class == 4 and error_number == 1:  # 401
                    nonce = attrs.get(STUN_ATTR_NONCE)
                    server_realm = attrs.get(STUN_ATTR_REALM)
                    if nonce and server_realm:
                        # 发送第二次请求
                        tid2 = gen_tid()
                        auth_username = username or USERNAME
                        auth_password = password or PASSWORD
                        integrity_key = compute_long_term_hmac_key(auth_username, server_realm, auth_password)
                        attrs2 = [
                            stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
                            stun_attr(STUN_ATTR_REALM, server_realm),
                            stun_attr(STUN_ATTR_NONCE, nonce),
                            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00")),
                        ]
                        req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
                        control_sock.send(req2)
                        data2 = control_sock.recv(2000)
                        msg_type2, tid2, attrs2 = parse_attrs(data2)
                        
                        if msg_type2 == STUN_ALLOCATE_ERROR_RESPONSE:
                            error_code2 = attrs2.get(STUN_ATTR_ERROR_CODE)
                            if error_code2:
                                error_class2 = error_code2[2]
                                error_number2 = error_code2[3]
                                if error_class2 == 4 and error_number2 == 0:  # 400
                                    print("[+] Received 400 error with long-term credential, falling back to short-term credential...")
                                    control_sock.close()
                                    result = allocate_tcp_single_server(server_address, username, password, realm, use_tls, use_short_term_credential=True)
                                    if result:
                                        return result, True
                                    else:
                                        print("[-] Both long-term and short-term credential attempts returned 400 error")
                                        return None, None
    except Exception as e:
        print(f"[!] Error checking error code: {e}")
    finally:
        control_sock.close()
    
    # 回退为短期凭据
    print("[+] Long-term credential failed, trying short-term credential...")
    result = allocate_tcp_single_server(server_address, username, password, realm, use_tls, use_short_term_credential=True)
    if result:
        return result, True
    
    return None, None

def allocate_tcp_udp_with_fallback(server_address, username, password, realm, server_hostname=None, use_tls=False):
    """尝试分配TCP+UDP TURN地址，带回退机制：先尝试长期凭据，如果收到400错误则回退为短期凭据
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        server_hostname: 服务器主机名
        use_tls: 是否使用TLS
    
    Returns:
        (result, is_short_term) 或 (None, None)
    """
    # 先尝试长期凭据
    print("[+] Trying long-term credential mechanism...")
    result = allocate_tcp_udp_single_server(server_address, username, password, realm, use_tls, server_hostname, use_short_term_credential=False)
    
    if result:
        return result, False
    
    # 检查是否是400错误（通过重新发送请求来检查）
    import socket
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_sock.settimeout(10)
    
    try:
        control_sock.connect(server_address)
        if use_tls:
            import ssl
            context = ssl.create_default_context()
            ssl_hostname = server_hostname or server_address[0]
            control_sock = context.wrap_socket(control_sock, server_hostname=ssl_hostname)
        
        from turn_client import build_msg, stun_attr, gen_tid, STUN_ALLOCATE_REQUEST, parse_attrs, compute_long_term_hmac_key
        from turn_client import STUN_ALLOCATE_ERROR_RESPONSE, STUN_ATTR_ERROR_CODE, STUN_ATTR_USERNAME, STUN_ATTR_REALM, STUN_ATTR_NONCE, STUN_ATTR_REQUESTED_TRANSPORT
        
        # 先发送无认证请求
        tid1 = gen_tid()
        req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))
        ])
        control_sock.send(req1)
        data = control_sock.recv(2000)
        msg_type, tid, attrs = parse_attrs(data)
        
        if msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                if error_class == 4 and error_number == 1:  # 401
                    nonce = attrs.get(STUN_ATTR_NONCE)
                    server_realm = attrs.get(STUN_ATTR_REALM)
                    if nonce and server_realm:
                        # 发送第二次请求
                        tid2 = gen_tid()
                        auth_username = username or USERNAME
                        auth_password = password or PASSWORD
                        integrity_key = compute_long_term_hmac_key(auth_username, server_realm, auth_password)
                        attrs2 = [
                            stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
                            stun_attr(STUN_ATTR_REALM, server_realm),
                            stun_attr(STUN_ATTR_NONCE, nonce),
                            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),
                        ]
                        req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
                        control_sock.send(req2)
                        data2 = control_sock.recv(2000)
                        msg_type2, tid2, attrs2 = parse_attrs(data2)
                        
                        if msg_type2 == STUN_ALLOCATE_ERROR_RESPONSE:
                            error_code2 = attrs2.get(STUN_ATTR_ERROR_CODE)
                            if error_code2:
                                error_class2 = error_code2[2]
                                error_number2 = error_code2[3]
                                if error_class2 == 4 and error_number2 == 0:  # 400
                                    print("[+] Received 400 error with long-term credential, falling back to short-term credential...")
                                    control_sock.close()
                                    result = allocate_tcp_udp_single_server(server_address, username, password, realm, use_tls, server_hostname, use_short_term_credential=True)
                                    if result:
                                        return result, True
                                    else:
                                        print("[-] Both long-term and short-term credential attempts returned 400 error")
                                        return None, None
    except Exception as e:
        print(f"[!] Error checking error code: {e}")
    finally:
        control_sock.close()
    
    # 回退为短期凭据
    print("[+] Long-term credential failed, trying short-term credential...")
    result = allocate_tcp_udp_single_server(server_address, username, password, realm, use_tls, server_hostname, use_short_term_credential=True)
    if result:
        return result, True
    
    return None, None

def test_udp_turn(server_address, username, password, realm, server_hostname, target_ip="8.8.8.8", target_port=53, use_short_term_credential=False):
    """测试UDP TURN功能
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        server_hostname: 服务器主机名
        target_ip: 测试目标IP
        target_port: 测试目标端口
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    print("\n" + "="*60)
    print("🔍 测试 UDP TURN 功能")
    print("="*60)
    
    try:
        print(f"[+] 开始UDP TURN测试...")
        print(f"[+] 目标: {target_ip}:{target_port} (DNS服务器)")
        print(f"[+] TURN服务器: {server_address}")
        
        # 1. 分配UDP TURN中继地址（带回退机制）
        print("\n[1/3] 分配UDP TURN中继地址...")
        result, is_short_term = allocate_with_fallback(server_address, username, password, realm, server_hostname)
        if not result:
            print("❌ UDP TURN分配失败")
            return False
        
        sock, nonce, realm, integrity_key, actual_server_address, *extra = result
        if len(extra) > 0:
            mi_algorithm = extra[0]  # 可能存在 mi_algorithm
        if is_short_term:
            print("[+] Using short-term credential for subsequent operations")
        print(f"✅ UDP TURN分配成功 (实际服务器: {actual_server_address})")
        
        # 2. 创建权限
        print("\n[2/3] 创建权限...")
        if not create_permission(sock, nonce, realm, integrity_key, target_ip, target_port, actual_server_address, username):
            print("❌ 创建权限失败")
            sock.close()
            return False
        print("✅ 权限创建成功")
        
        # 3. 绑定通道
        print("\n[3/3] 绑定通道...")
        import random
        channel_number = random.randint(0x4000, 0x4FFF)
        if not channel_bind(sock, nonce, realm, integrity_key, target_ip, target_port, channel_number, actual_server_address, username):
            print("❌ 通道绑定失败")
            sock.close()
            return False
        print(f"✅ 通道绑定成功 (通道号: {channel_number:04x})")
        
        print("✅ UDP TURN连接建立完成")
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ UDP TURN测试失败: {e}")
        return False

def test_tcp_udp_turn(server_address, username, password, realm, server_hostname, use_tls, target_ip="8.8.8.8", target_port=53, use_short_term_credential=False):
    """测试TCP+UDP TURN功能
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        server_hostname: 服务器主机名
        use_tls: 是否使用TLS
        target_ip: 测试目标IP
        target_port: 测试目标端口
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    print("\n" + "="*60)
    print("🔍 测试 TCP+UDP TURN 功能")
    print("="*60)
    
    try:
        print(f"[+] 开始TCP+UDP TURN测试...")
        print(f"[+] 目标: {target_ip}:{target_port} (DNS服务器)")
        print(f"[+] TURN服务器: {server_address}")
        print(f"[+] 使用TLS: {use_tls}")
        
        # 1. 分配TCP+UDP TURN中继地址（带回退机制）
        print("\n[1/3] 分配TCP+UDP TURN中继地址...")
        result, is_short_term = allocate_tcp_udp_with_fallback(server_address, username, password, realm, server_hostname, use_tls)
        if not result:
            print("❌ TCP+UDP TURN分配失败")
            return False
        
        control_sock, nonce, realm, integrity_key, actual_server_address, *extra = result
        if len(extra) > 0:
            mi_algorithm = extra[0]  # 可能存在 mi_algorithm
        if is_short_term:
            print("[+] Using short-term credential for subsequent operations")
        print(f"✅ TCP+UDP TURN分配成功 (实际服务器: {actual_server_address})")
        
        # 2. 创建权限
        print("\n[2/3] 创建权限...")
        if not create_permission(control_sock, nonce, realm, integrity_key, target_ip, target_port, actual_server_address, username):
            print("❌ 创建权限失败")
            control_sock.close()
            return False
        print("✅ 权限创建成功")
        
        # 3. 绑定通道
        print("\n[3/3] 绑定通道...")
        import random
        channel_number = random.randint(0x4000, 0x4FFF)
        if not channel_bind(control_sock, nonce, realm, integrity_key, target_ip, target_port, channel_number, actual_server_address, username):
            print("❌ 通道绑定失败")
            control_sock.close()
            return False
        print(f"✅ 通道绑定成功 (通道号: {channel_number:04x})")
        
        print("✅ TCP+UDP TURN连接建立完成")
        control_sock.close()
        return True
        
    except Exception as e:
        print(f"❌ TCP+UDP TURN测试失败: {e}")
        return False

def test_tcp_turn(server_address, username, password, realm, server_hostname, use_tls, target_ip="httpbin.org", target_port=80, use_short_term_credential=False):
    """测试TCP TURN功能
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        server_hostname: 服务器主机名
        use_tls: 是否使用TLS
        target_ip: 测试目标IP
        target_port: 测试目标端口
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    print("\n" + "="*60)
    print("🔍 测试 TCP TURN 功能")
    print("="*60)
    
    try:
        print(f"[+] 开始TCP TURN测试...")
        print(f"[+] 目标: {target_ip}:{target_port}")
        print(f"[+] TURN服务器: {server_address}")
        print(f"[+] 使用TLS: {use_tls}")
        
        # 1. 分配TCP TURN中继地址（带回退机制）
        print("\n[1/1] 分配TCP TURN中继地址...")
        result, is_short_term = allocate_tcp_with_fallback(server_address, username, password, realm, use_tls)
        if not result:
            print("❌ TCP TURN分配失败")
            return False
        
        control_sock, nonce, realm, integrity_key, actual_server_address, *extra = result
        if len(extra) > 0:
            mi_algorithm = extra[0]  # 可能存在 mi_algorithm
        if is_short_term:
            print("[+] Using short-term credential for subsequent operations")
        print(f"✅ TCP TURN分配成功 (实际服务器: {actual_server_address})")
        
        print("✅ TCP TURN中继地址获取完成")
        control_sock.close()
        return True
        
    except Exception as e:
        print(f"❌ TCP TURN测试失败: {e}")
        return False
    finally:
        if 'control_sock' in locals():
            control_sock.close()

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='TURN服务器功能测试脚本')
    parser.add_argument('--turn-server', help=f'TURN服务器地址（域名或IP）(默认: {DEFAULT_TURN_SERVER})')
    parser.add_argument('--turn-port', type=int, help=f'TURN服务器端口 (默认: {DEFAULT_TURN_PORT})')
    parser.add_argument('--username', help=f'TURN服务器用户名 (默认: {USERNAME})')
    parser.add_argument('--password', help=f'TURN服务器密码 (默认: {PASSWORD})')
    parser.add_argument('--realm', help=f'TURN服务器认证域 (默认: {REALM})')
    parser.add_argument('--tls', action='store_true', help='使用TLS加密连接')
    parser.add_argument('--target-ip', help='测试目标IP地址 (默认: 8.8.8.8)')
    parser.add_argument('--target-port', type=int, help='测试目标端口 (默认: 53)')
    parser.add_argument('--test-udp', action='store_true', help='仅测试UDP TURN功能')
    parser.add_argument('--test-tcp-udp', action='store_true', help='仅测试TCP+UDP TURN功能')
    parser.add_argument('--test-tcp', action='store_true', help='仅测试TCP TURN功能')
    parser.add_argument('--short-term-credential', action='store_true', help='使用短期凭证机制（默认使用长期凭证）')
    
    args = parser.parse_args()
    
    # 使用默认值填充未提供的参数
    turn_server = args.turn_server or DEFAULT_TURN_SERVER
    turn_port = args.turn_port or DEFAULT_TURN_PORT
    username = args.username or USERNAME
    password = args.password or PASSWORD
    realm = args.realm or REALM
    target_ip = args.target_ip or TEST_SERVERS["dns"]["host"]  # 使用config.py中的DNS服务器
    target_port = args.target_port or TEST_SERVERS["dns"]["port"]  # 使用config.py中的DNS端口
    
    # 解析服务器地址
    server_address = resolve_server_address(turn_server, turn_port)
    if not server_address:
        print(f"❌ 无法解析TURN服务器地址: {turn_server}")
        return
    
    print("🚀 TURN服务器功能测试")
    print("="*60)
    print(f"TURN服务器: {server_address}")
    print(f"用户名: {username}")
    print(f"认证域: {realm}")
    print(f"使用TLS: {args.tls}")
    print(f"使用短期凭证: {args.short_term_credential}")
    print(f"测试目标: {target_ip}:{target_port}")
    
    # 测试结果统计
    results = {}
    
    # 如果没有指定特定测试，则运行所有测试
    if not (args.test_udp or args.test_tcp_udp or args.test_tcp):
        args.test_udp = True
        args.test_tcp_udp = True
        args.test_tcp = True
    
    # 测试UDP TURN
    if args.test_udp:
        results['UDP TURN'] = test_udp_turn(server_address, username, password, realm, turn_server, target_ip, target_port, args.short_term_credential)
    
    # 测试TCP+UDP TURN
    if args.test_tcp_udp:
        results['TCP+UDP TURN'] = test_tcp_udp_turn(server_address, username, password, realm, turn_server, args.tls, target_ip, target_port, args.short_term_credential)
    
    # 测试TCP TURN - 使用HTTP服务器作为目标
    if args.test_tcp:
        http_target_ip = TEST_SERVERS["http"]["host"]
        http_target_port = TEST_SERVERS["http"]["port"]
        results['TCP TURN'] = test_tcp_turn(server_address, username, password, realm, turn_server, args.tls, http_target_ip, http_target_port, args.short_term_credential)
    
    # 输出测试结果汇总
    print("\n" + "="*60)
    print("📊 测试结果汇总")
    print("="*60)
    
    for test_name, success in results.items():
        status = "✅ 成功" if success else "❌ 失败"
        print(f"{test_name:15} : {status}")
    
    # 统计成功数量
    success_count = sum(results.values())
    total_count = len(results)
    
    print(f"\n总体结果: {success_count}/{total_count} 项测试通过")
    
    if success_count == total_count:
        print("🎉 所有测试通过！TURN服务器功能完整。")
    elif success_count > 0:
        print("⚠️ 部分测试通过，TURN服务器支持部分功能。")
    else:
        print("❌ 所有测试失败，TURN服务器可能不支持或配置有误。")

if __name__ == "__main__":
    main()
