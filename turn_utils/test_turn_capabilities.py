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
import sys
import os
# 添加父目录到路径，以便导入config模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # 作为包的一部分导入
    from .turn_client import (
        allocate, allocate_tcp_udp, allocate_tcp,
        create_permission, channel_bind, channel_data, channel_data_tcp,
        tcp_connect, tcp_connection_bind, tcp_send_data, tcp_receive_data,
        resolve_server_address, resolve_peer_address
    )
except ImportError:
    # 作为独立脚本导入
    from turn_client import (
        allocate, allocate_tcp_udp, allocate_tcp,
        create_permission, channel_bind, channel_data, channel_data_tcp,
        tcp_connect, tcp_connection_bind, tcp_send_data, tcp_receive_data,
        resolve_server_address, resolve_peer_address
    )
from config import (
    DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT, USERNAME, PASSWORD, REALM,
    TEST_SERVERS
)

def test_udp_turn(server_address, username, password, realm, server_hostname, target_ip="8.8.8.8", target_port=53):
    """测试UDP TURN功能"""
    print("\n" + "="*60)
    print("🔍 测试 UDP TURN 功能")
    print("="*60)
    
    try:
        print(f"[+] 开始UDP TURN测试...")
        print(f"[+] 目标: {target_ip}:{target_port} (DNS服务器)")
        print(f"[+] TURN服务器: {server_address}")
        
        # 1. 分配UDP TURN中继地址
        print("\n[1/3] 分配UDP TURN中继地址...")
        result = allocate(server_address, username, password, realm, server_hostname)
        if not result:
            print("❌ UDP TURN分配失败")
            return False
        
        sock, nonce, realm, integrity_key, actual_server_address = result
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

def test_tcp_udp_turn(server_address, username, password, realm, server_hostname, use_tls, target_ip="8.8.8.8", target_port=53):
    """测试TCP+UDP TURN功能"""
    print("\n" + "="*60)
    print("🔍 测试 TCP+UDP TURN 功能")
    print("="*60)
    
    try:
        print(f"[+] 开始TCP+UDP TURN测试...")
        print(f"[+] 目标: {target_ip}:{target_port} (DNS服务器)")
        print(f"[+] TURN服务器: {server_address}")
        print(f"[+] 使用TLS: {use_tls}")
        
        # 1. 分配TCP+UDP TURN中继地址
        print("\n[1/3] 分配TCP+UDP TURN中继地址...")
        result = allocate_tcp_udp(server_address, username, password, realm, use_tls, server_hostname)
        if not result:
            print("❌ TCP+UDP TURN分配失败")
            return False
        
        control_sock, nonce, realm, integrity_key, actual_server_address = result
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

def test_tcp_turn(server_address, username, password, realm, server_hostname, use_tls, target_ip="httpbin.org", target_port=80):
    """测试TCP TURN功能"""
    print("\n" + "="*60)
    print("🔍 测试 TCP TURN 功能")
    print("="*60)
    
    try:
        print(f"[+] 开始TCP TURN测试...")
        print(f"[+] 目标: {target_ip}:{target_port}")
        print(f"[+] TURN服务器: {server_address}")
        print(f"[+] 使用TLS: {use_tls}")
        
        # 1. 分配TCP TURN中继地址
        print("\n[1/1] 分配TCP TURN中继地址...")
        result = allocate_tcp(server_address, username, password, realm, use_tls, server_hostname)
        if not result:
            print("❌ TCP TURN分配失败")
            return False
        
        control_sock, nonce, realm, integrity_key, actual_server_address = result
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
        results['UDP TURN'] = test_udp_turn(server_address, username, password, realm, turn_server, target_ip, target_port)
    
    # 测试TCP+UDP TURN
    if args.test_tcp_udp:
        results['TCP+UDP TURN'] = test_tcp_udp_turn(server_address, username, password, realm, turn_server, args.tls, target_ip, target_port)
    
    # 测试TCP TURN - 使用HTTP服务器作为目标
    if args.test_tcp:
        http_target_ip = TEST_SERVERS["http"]["host"]
        http_target_port = TEST_SERVERS["http"]["port"]
        results['TCP TURN'] = test_tcp_turn(server_address, username, password, realm, turn_server, args.tls, http_target_ip, http_target_port)
    
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
