#!/usr/bin/env python3
"""
通过 TURN 服务器进行 UDP 端口扫描
使用 ICMP 端口不可达错误来判断端口状态（类似 nmap）

基于 RFC 8656:
- 发送空的 UDP 数据包（通过 ChannelData）
- 接收 ICMP 错误消息（通过 Data indication with ICMP attribute）
- ICMP 类型 3，代码 3 = 端口不可达（端口关闭）
- 无 ICMP 响应 = 端口可能开放或被过滤
"""

import socket
import struct
import sys
import os
import time
import argparse

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT, USERNAME, PASSWORD, REALM

# 导入 TURN 客户端函数
from turn_client import (
    allocate_single_server, create_permission, resolve_server_address,
    resolve_peer_address, parse_attrs,
    STUN_MAGIC_COOKIE, channel_bind, channel_data
)
from test_turn_capabilities import allocate_with_fallback

# STUN 消息类型（RFC 8656）
STUN_DATA_INDICATION = 0x0117

# STUN 属性类型（RFC 8656）
STUN_ATTR_ICMP = 0x8004

# ICMP 类型和代码
ICMP_DEST_UNREACH = 3
ICMP_PORT_UNREACH = 3  # ICMP 代码 3 = 端口不可达


def send_udp_packet(sock, server_address, nonce, realm, integrity_key, peer_ip, peer_port, channel_number, data=b"", username=None, mi_algorithm=None):
    """
    通过 TURN 服务器发送 UDP 数据包（使用 ChannelData）
    
    Args:
        sock: TURN 控制 socket
        server_address: TURN 服务器地址 (ip, port)
        nonce: STUN nonce
        realm: STUN realm
        integrity_key: 完整性密钥
        peer_ip: 目标 IP 地址
        peer_port: 目标端口
        channel_number: Channel 号码（0x4000-0x4FFF）
        data: 要发送的数据（空包用于端口扫描）
        username: TURN 用户名
        mi_algorithm: 消息完整性算法
    
    Returns:
        bool: 是否发送成功
    """
    # 1. 先绑定 channel（如果还没有绑定）
    print(f"[+] Binding channel {channel_number} to {peer_ip}:{peer_port}")
    if not channel_bind(sock, nonce, realm, integrity_key, peer_ip, peer_port, channel_number, 
                       server_address, username, mi_algorithm):
        print(f"[-] Failed to bind channel {channel_number}")
        return False
    
    # 2. 使用 ChannelData 发送数据
    print(f"[+] Sending UDP packet via channel {channel_number} to {peer_ip}:{peer_port} (size: {len(data)} bytes)")
    if not channel_data(sock, channel_number, data, server_address):
        print(f"[-] Failed to send ChannelData")
        return False
    
    return True


def receive_icmp_error(sock, timeout=3):
    """
    接收 ICMP 错误消息（通过 Data indication with ICMP attribute）
    
    Args:
        sock: TURN 控制 socket
        timeout: 超时时间（秒）
    
    Returns:
        tuple: (icmp_type, icmp_code, peer_address) 或 (None, None, None)
    """
    sock.settimeout(timeout)
    
    try:
        data, addr = sock.recvfrom(2048)
        print(f"[+] Received {len(data)} bytes from {addr}")
        msg_type, tid, attrs = parse_attrs(data)
        print(f"[+] Message type: 0x{msg_type:04x}, Attributes: {list(attrs.keys())}")
        
        # 检查是否是 Data indication (0x0117)
        if msg_type == STUN_DATA_INDICATION:
            # 检查是否包含 ICMP 属性
            icmp_attr = attrs.get(STUN_ATTR_ICMP)
            xor_peer_attr = attrs.get(STUN_ATTR_XOR_PEER_ADDRESS)
            
            if icmp_attr and xor_peer_attr:
                # 解析 ICMP 属性（RFC 8656 Section 18.13）
                if len(icmp_attr) >= 8:
                    # 格式: Reserved(2) + ICMP Type(1) + ICMP Code(1) + Error Data(4)
                    icmp_type = icmp_attr[2]
                    icmp_code = icmp_attr[3]
                    
                    # 解析 XOR-PEER-ADDRESS
                    if len(xor_peer_attr) >= 8:
                        family = xor_peer_attr[1]
                        if family == 1:  # IPv4
                            xor_port = struct.unpack("!H", xor_peer_attr[2:4])[0]
                            xor_ip = xor_peer_attr[4:8]
                            # 解码 XOR IP
                            peer_ip = socket.inet_ntoa(bytes([xor_ip[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)]))
                            peer_port = xor_port ^ (STUN_MAGIC_COOKIE >> 16)
                            peer_address = (peer_ip, peer_port)
                            
                            print(f"[+] Received ICMP error: Type={icmp_type}, Code={icmp_code} from {peer_address}")
                            return (icmp_type, icmp_code, peer_address)
            
            # 如果收到 Data indication 但没有 ICMP 属性，可能是正常数据
            if msg_type == STUN_DATA_INDICATION:
                print("[+] Received Data indication (no ICMP attribute)")
        else:
            # 检查是否是错误响应
            error_code = attrs.get(9)  # STUN_ATTR_ERROR_CODE
            if error_code:
                error_class = error_code[2] if len(error_code) > 2 else 0
                error_number = error_code[3] if len(error_code) > 3 else 0
                error_reason = error_code[4:].decode('utf-8', errors='ignore') if len(error_code) > 4 else ""
                print(f"[!] Received error response: {error_class}{error_number:02d} {error_reason}")
                # 如果是 401 错误，根据 RFC 8656 Section 5，indications 不应该被认证
                # 这可能是服务器实现问题，忽略并继续等待 ICMP 响应
                if error_class == 4 and error_number == 1:
                    print("[!] Ignoring 401 error (RFC 8656 Section 5: indications are never authenticated)")
                    print("[!] This is likely a server implementation issue, continuing to wait for ICMP...")
                    # 继续等待，不返回
                    return receive_icmp_error(sock, timeout)  # 递归调用继续等待
            else:
                print(f"[!] Received unexpected message type: 0x{msg_type:04x}")
        
    except socket.timeout:
        print(f"[+] No ICMP error received within {timeout} seconds")
    except Exception as e:
        print(f"[-] Error receiving data: {e}")
        import traceback
        traceback.print_exc()
    
    return (None, None, None)


def scan_udp_port(turn_server, turn_port, username, password, realm, 
                  target_ip, target_port, timeout=3):
    """
    扫描单个 UDP 端口
    
    Args:
        turn_server: TURN 服务器地址
        turn_port: TURN 服务器端口
        username: TURN 用户名
        password: TURN 密码
        realm: TURN realm
        target_ip: 目标 IP 地址
        target_port: 目标端口
        timeout: 超时时间（秒）
    
    Returns:
        str: 端口状态 ("open", "closed", "filtered", "error")
    """
    print(f"\n{'='*60}")
    print(f"扫描端口: {target_ip}:{target_port}")
    print(f"{'='*60}")
    
    # 1. 分配 UDP TURN 中继地址（使用回退机制）
    server_address = resolve_server_address(turn_server, turn_port)
    if not server_address:
        print("[-] Failed to resolve TURN server address")
        return "error"
    
    print(f"[+] Using TURN server: {server_address}")
    allocation_result, is_short_term = allocate_with_fallback(
        server_address, username, password, realm, turn_server
    )
    
    if not allocation_result:
        print("[-] Failed to allocate UDP TURN relay")
        return "error"
    
    sock, nonce, realm, integrity_key, actual_server_address, *extra = allocation_result
    mi_algorithm = extra[0] if len(extra) > 0 else None
    
    if is_short_term:
        print("[+] UDP TURN allocation successful (using short-term credential)")
    else:
        print("[+] UDP TURN allocation successful (using long-term credential)")
    
    try:
        # 2. 创建权限
        print(f"[+] Creating permission for {target_ip}:{target_port}")
        if not create_permission(sock, nonce, realm, integrity_key, target_ip, target_port, 
                                 actual_server_address, username, mi_algorithm):
            print("[-] Failed to create permission")
            return "error"
        print("[+] Permission created successfully")
        
        # 3. 发送空的 UDP 数据包（使用 ChannelData）
        print(f"[+] Sending empty UDP packet to {target_ip}:{target_port}")
        channel_number = 0x4000  # 使用第一个可用 channel 号
        if not send_udp_packet(sock, actual_server_address, nonce, realm, integrity_key, 
                               target_ip, target_port, channel_number, b"", username, mi_algorithm):
            return "error"
        
        # 4. 等待并接收 ICMP 错误消息（多次尝试，因为可能先收到错误响应）
        print(f"[+] Waiting for ICMP error (timeout: {timeout}s)...")
        icmp_type, icmp_code, peer_addr = None, None, None
        
        # 多次尝试接收，因为可能先收到其他响应
        max_attempts = 3
        for attempt in range(max_attempts):
            result = receive_icmp_error(sock, timeout // max_attempts + 1)
            if result[0] is not None:  # 收到 ICMP 错误
                icmp_type, icmp_code, peer_addr = result
                break
            if attempt < max_attempts - 1:
                time.sleep(0.3)  # 短暂等待后重试
        
        # 5. 判断端口状态
        if icmp_type == ICMP_DEST_UNREACH and icmp_code == ICMP_PORT_UNREACH:
            print(f"[+] Port {target_port} is CLOSED (ICMP Port Unreachable)")
            return "closed"
        elif icmp_type is not None:
            print(f"[+] Port {target_port} status: ICMP Type={icmp_type}, Code={icmp_code}")
            return "filtered"
        else:
            print(f"[+] Port {target_port} is OPEN or FILTERED (no ICMP error)")
            return "open|filtered"
    
    finally:
        sock.close()


def scan_multiple_ports(turn_server, turn_port, username, password, realm,
                        target_ip, ports, timeout=3):
    """
    扫描多个 UDP 端口
    
    Args:
        turn_server: TURN 服务器地址
        turn_port: TURN 服务器端口
        username: TURN 用户名
        password: TURN 密码
        realm: TURN realm
        target_ip: 目标 IP 地址
        ports: 端口列表
        timeout: 超时时间（秒）
    
    Returns:
        dict: {port: status}
    """
    results = {}
    
    print(f"\n{'='*70}")
    print(f"UDP 端口扫描 - 目标: {target_ip}")
    print(f"TURN 服务器: {turn_server}:{turn_port}")
    print(f"端口数量: {len(ports)}")
    print(f"发送方式: ChannelData")
    print(f"{'='*70}")
    
    for port in ports:
        status = scan_udp_port(turn_server, turn_port, username, password, realm,
                              target_ip, port, timeout)
        results[port] = status
        time.sleep(0.5)  # 避免请求过快
    
    # 打印汇总
    print(f"\n{'='*70}")
    print("扫描结果汇总:")
    print(f"{'='*70}")
    for port, status in sorted(results.items()):
        print(f"  {port:5d}: {status}")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="通过 TURN 服务器进行 UDP 端口扫描（使用 ICMP 端口不可达错误）"
    )
    parser.add_argument("--turn-server", required=True, help="TURN 服务器地址")
    parser.add_argument("--turn-port", type=int, default=3478, help="TURN 服务器端口")
    parser.add_argument("--username", required=True, help="TURN 用户名")
    parser.add_argument("--password", required=True, help="TURN 密码")
    parser.add_argument("--realm", help="TURN realm")
    parser.add_argument("--target", required=True, help="目标 IP 地址")
    parser.add_argument("--ports", required=True, help="端口列表（逗号分隔）或端口范围（如 80-100）")
    parser.add_argument("--timeout", type=int, default=3, help="超时时间（秒）")
    
    args = parser.parse_args()
    
    # 解析端口列表
    ports = []
    if ',' in args.ports:
        # 逗号分隔的端口列表
        ports = [int(p.strip()) for p in args.ports.split(',')]
    elif '-' in args.ports:
        # 端口范围
        start, end = map(int, args.ports.split('-'))
        ports = list(range(start, end + 1))
    else:
        # 单个端口
        ports = [int(args.ports)]
    
    # 执行扫描
    results = scan_multiple_ports(
        args.turn_server, args.turn_port,
        args.username, args.password, args.realm,
        args.target, ports, args.timeout
    )
    
    # 统计结果
    open_count = sum(1 for s in results.values() if s == "open|filtered")
    closed_count = sum(1 for s in results.values() if s == "closed")
    filtered_count = sum(1 for s in results.values() if s == "filtered")
    error_count = sum(1 for s in results.values() if s == "error")
    
    print(f"\n统计:")
    print(f"  开放/过滤: {open_count}")
    print(f"  关闭: {closed_count}")
    print(f"  过滤: {filtered_count}")
    print(f"  错误: {error_count}")
    print(f"  总计: {len(results)}")


if __name__ == "__main__":
    main()
