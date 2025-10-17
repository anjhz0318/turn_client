#!/usr/bin/env python3
"""
临时HTTP测试脚本 - 测试新TURN服务器
"""

import socket
import ssl
import sys
from turn_client import (
    allocate_tcp, tcp_connection_bind, tcp_send_data, tcp_receive_data,
    resolve_server_address, resolve_peer_address, tcp_connect
)

def test_http_with_custom_turn(target_host, target_port=80, turn_server=None, turn_port=None, 
                              username=None, password=None, realm=None):
    """测试HTTP客户端通过自定义TURN服务器"""
    print(f"[+] Testing HTTP via TURN: {target_host}:{target_port}")
    print(f"[+] TURN Server: {turn_server}:{turn_port}")
    print(f"[+] Username: {username}")
    print(f"[+] Realm: {realm}")
    
    # 解析TURN服务器地址
    server_address = resolve_server_address(turn_server, turn_port)
    if not server_address:
        print("[-] Failed to resolve TURN server address")
        return False
        
    print(f"[+] Using TURN server: {server_address}")
    
    try:
        # 1. 分配TCP TURN中继地址
        result = allocate_tcp(server_address, username, password, realm)
        if not result:
            print("[-] Failed to allocate TCP TURN relay")
            return False
            
        control_sock, nonce, realm, integrity_key = result
        print("[+] TCP TURN allocation successful")
        
        # 2. 发起TCP连接到目标HTTP服务器
        peer_ip = resolve_peer_address(target_host)
        if not peer_ip:
            print(f"[-] Failed to resolve peer {target_host}")
            control_sock.close()
            return False
            
        print(f"[+] Initiating TCP connection to {target_host}:{target_port}")
        print(f"[+] Resolved peer {target_host} to {peer_ip}")
        
        connection_id = tcp_connect(control_sock, nonce, realm, integrity_key, peer_ip, target_port)
        if not connection_id:
            print("[-] Failed to initiate TCP connection")
            control_sock.close()
            return False
            
        print(f"[+] Got connection ID: {connection_id}")
        
        # 3. 建立数据连接
        data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_sock.settimeout(10)
        data_sock.connect(server_address)
        print("[+] Data connection established")
        
        # 4. 绑定数据连接到对等方连接
        if not tcp_connection_bind(data_sock, nonce, realm, integrity_key, connection_id, server_address):
            print("[-] Failed to bind data connection")
            data_sock.close()
            control_sock.close()
            return False
            
        print("[+] Data connection bound successfully")
        
        # 5. 发送HTTP请求
        host_header = f"{target_host}:{target_port}" if target_port != 80 else target_host
        request = f"GET / HTTP/1.1\r\nHost: {host_header}\r\n\r\n"
        
        print(f"[+] Sending HTTP request:")
        print(f"    GET / HTTP/1.1")
        print(f"    Host: {host_header}")
        
        if not tcp_send_data(data_sock, request.encode('utf-8')):
            print("[-] Failed to send HTTP request")
            data_sock.close()
            control_sock.close()
            return False
            
        print("[+] HTTP request sent successfully")
        
        # 6. 接收响应
        print("[+] Waiting for HTTP response...")
        try:
            data_sock.settimeout(30)
            response_data = b""
            
            # 接收响应头
            while True:
                chunk = data_sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                
                # 检查是否收到完整的响应头
                if b"\r\n\r\n" in response_data:
                    break
                    
            if response_data:
                response_text = response_data.decode('utf-8', errors='ignore')
                print(f"[+] Received HTTP response ({len(response_data)} bytes)")
                print("\n=== HTTP Response ===")
                print(response_text[:500] + "..." if len(response_text) > 500 else response_text)
                return True
            else:
                print("[-] No response received")
                return False
                
        except socket.timeout:
            print("[-] Timeout waiting for response")
            return False
            
    except Exception as e:
        print(f"[-] HTTP test failed: {e}")
        return False
    finally:
        # 清理连接
        try:
            if 'data_sock' in locals():
                data_sock.close()
            if 'control_sock' in locals():
                control_sock.close()
        except:
            pass

if __name__ == "__main__":
    # 测试新的TURN服务器
    success = test_http_with_custom_turn(
        target_host="httpbin.org",
        target_port=80,
        turn_server="144.196.192.188",
        turn_port=5004,
        username="webxturnreachuser",
        password="webexturnreachpwd",
        realm="webex.com"
    )
    
    if success:
        print("\n🎉 HTTP测试成功！")
    else:
        print("\n❌ HTTP测试失败")
    
    sys.exit(0 if success else 1)
