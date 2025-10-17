#!/usr/bin/env python3
"""
HTTP Client via TCP TURN
支持HTTP/1.1和HTTP/2请求通过TURN服务器转发
"""

import socket
import ssl
import argparse
import sys
from turn_client import (
    allocate_tcp, tcp_connection_bind, tcp_send_data, tcp_receive_data,
    resolve_server_address, resolve_peer_address, tcp_connect
)
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

class HTTPTURNClient:
    def __init__(self, target_host, target_port=80, use_https=False, turn_server=None, turn_port=None, username=None, password=None, realm=None, use_tls=False):
        self.target_host = target_host
        self.target_port = target_port
        self.use_https = use_https
        self.turn_server = turn_server or DEFAULT_TURN_SERVER
        self.turn_port = turn_port or DEFAULT_TURN_PORT
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls
        
        self.control_sock = None
        self.data_sock = None
        self.connected = False
        
    def connect(self):
        """连接到目标HTTP服务器 - 完全照搬demo_tcp_with_data_connection的逻辑"""
        print(f"[+] Connecting to HTTP server {self.target_host}:{self.target_port} via TURN")
        
        # 解析TURN服务器地址
        server_address = resolve_server_address(self.turn_server, self.turn_port)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return False
            
        print(f"[+] Using TURN server: {server_address}")
        
        try:
            # 1. 分配TCP TURN中继地址
            result = allocate_tcp(server_address, self.username, self.password, self.realm, self.use_tls)
            if not result:
                print("[-] Failed to allocate TCP TURN relay")
                return False
                
            self.control_sock, nonce, realm, integrity_key = result
            print("[+] TCP TURN allocation successful")
            
            # 2. 发起TCP连接到对等方
            peer_ip = resolve_peer_address(self.target_host)
            if not peer_ip:
                print(f"[-] Failed to resolve peer {self.target_host}")
                self.control_sock.close()
                return False
                
            print(f"[+] Initiating TCP connection to {self.target_host}:{self.target_port}")
            print(f"[+] Resolved peer {self.target_host} to {peer_ip}")
            
            connection_id = tcp_connect(self.control_sock, nonce, realm, integrity_key, peer_ip, self.target_port)
            if not connection_id:
                print("[-] Failed to initiate TCP connection")
                self.control_sock.close()
                return False
                
            print(f"[+] Got connection ID: {connection_id}")
            
            # 3. 建立数据连接
            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_sock.settimeout(10)
            self.data_sock.connect(server_address)
            print("[+] Data connection established")
            
            # 4. 绑定数据连接到对等方连接
            if not tcp_connection_bind(self.data_sock, nonce, realm, integrity_key, connection_id, server_address):
                print("[-] Failed to bind data connection")
                self.data_sock.close()
                self.control_sock.close()
                return False
                
            print("[+] Data connection bound successfully")
            
            # 5. 如果是HTTPS，建立SSL连接
            if self.use_https:
                print("[+] Establishing SSL/TLS connection...")
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    self.data_sock = context.wrap_socket(self.data_sock, server_hostname=self.target_host)
                    print("[+] SSL/TLS connection established")
                    print(f"[+] SSL version: {self.data_sock.version()}")
                    print(f"[+] SSL cipher: {self.data_sock.cipher()}")
                except Exception as e:
                    print(f"[-] SSL/TLS connection failed: {e}")
                    self.data_sock.close()
                    self.control_sock.close()
                    return False
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            if self.control_sock:
                self.control_sock.close()
            if self.data_sock:
                self.data_sock.close()
            return False
    
    def send_http_request(self, method="GET", path="/", headers=None, body=None):
        """发送HTTP请求 - 完全照搬demo_tcp_with_data_connection的逻辑"""
        if not self.connected:
            print("[-] Not connected")
            return None
            
        # 构建HTTP请求
        if self.use_https:
            host_header = f"{self.target_host}:{self.target_port}" if self.target_port != 443 else self.target_host
        else:
            host_header = f"{self.target_host}:{self.target_port}" if self.target_port != 80 else self.target_host
            
        # 使用简化的HTTP格式，就像TCP TURN测试一样
        request = f"{method} {path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"
        
        print(f"[+] Sending HTTP request:")
        print(f"    {method} {path} HTTP/1.1")
        print(f"    Host: {host_header}")
        
        try:
            # 发送请求 - 使用tcp_send_data函数
            if not tcp_send_data(self.data_sock, request.encode('utf-8')):
                print("[-] Failed to send HTTP request")
                return None
                
            print("[+] HTTP request sent successfully")
            
            # 接收完整响应
            print("[+] Waiting for HTTP response...")
            response_data = self._receive_complete_response()
            if response_data:
                print(f"[+] Received complete response ({len(response_data)} bytes)")
                return response_data.decode('utf-8', errors='ignore')
            else:
                print("[-] No response received")
                return None
                
        except Exception as e:
            print(f"[-] Request failed: {e}")
            return None
    
    def _receive_complete_response(self):
        """接收完整的HTTP响应"""
        try:
            # 设置较长的超时时间
            self.data_sock.settimeout(30)
            
            # 接收响应头
            response_data = b""
            header_complete = False
            content_length = None
            
            while not header_complete:
                try:
                    chunk = self.data_sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    
                    # 检查是否收到完整的响应头
                    if b"\r\n\r\n" in response_data:
                        header_complete = True
                        
                        # 解析Content-Length
                        header_text = response_data[:response_data.find(b"\r\n\r\n")].decode('utf-8', errors='ignore')
                        for line in header_text.split('\r\n'):
                            if line.lower().startswith('content-length:'):
                                try:
                                    content_length = int(line.split(':', 1)[1].strip())
                                    print(f"[+] Content-Length: {content_length}")
                                    break
                                except ValueError:
                                    pass
                                    
                except socket.timeout:
                    print("[-] Timeout waiting for response")
                    break
            
            if not header_complete:
                print("[-] Incomplete response headers")
                return response_data
            
            # 计算已接收的响应体长度
            header_end = response_data.find(b"\r\n\r\n") + 4
            body_received = len(response_data) - header_end
            
            print(f"[+] Headers complete, body received: {body_received}/{content_length or 'unknown'}")
            
            # 如果有Content-Length，继续接收直到完整
            if content_length is not None:
                while body_received < content_length:
                    try:
                        chunk = self.data_sock.recv(min(4096, content_length - body_received))
                        if not chunk:
                            print("[-] Connection closed before complete response")
                            break
                        response_data += chunk
                        body_received = len(response_data) - header_end
                        print(f"[+] Progress: {body_received}/{content_length} bytes")
                    except socket.timeout:
                        print("[-] Timeout waiting for response body")
                        break
            else:
                # 没有Content-Length，尝试接收更多数据直到超时
                print("[+] No Content-Length, receiving until timeout...")
                try:
                    while True:
                        chunk = self.data_sock.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        print(f"[+] Received additional {len(chunk)} bytes")
                except socket.timeout:
                    print("[+] Timeout reached, assuming response complete")
            
            return response_data
            
        except Exception as e:
            print(f"[-] Error receiving response: {e}")
            return None
    
    def disconnect(self):
        """断开连接"""
        if self.connected:
            print("[+] Disconnecting...")
            if self.data_sock:
                self.data_sock.close()
            if self.control_sock:
                self.control_sock.close()
            self.connected = False
            print("[+] Disconnected")

def main():
    parser = argparse.ArgumentParser(description="HTTP Client via TCP TURN")
    parser.add_argument("--target-host", required=True, help="Target HTTP server hostname")
    parser.add_argument("--target-port", type=int, default=80, help="Target HTTP server port")
    parser.add_argument("--method", default="GET", help="HTTP method (GET, POST, HEAD)")
    parser.add_argument("--path", default="/", help="HTTP request path")
    parser.add_argument("--headers", help="Custom headers (format: 'Header1: Value1,Header2: Value2')")
    parser.add_argument("--body", help="Request body")
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--turn-server", help="TURN server hostname")
    parser.add_argument("--turn-port", type=int, help="TURN server port")
    parser.add_argument("--username", help="TURN server username")
    parser.add_argument("--password", help="TURN server password")
    parser.add_argument("--realm", help="TURN server realm")
    parser.add_argument("--tls", action="store_true", help="Use TLS for TURN server connection")
    
    args = parser.parse_args()
    
    # 解析自定义头部
    headers = {}
    if args.headers:
        for header in args.headers.split(','):
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # 设置默认端口
    if args.https and args.target_port == 80:
        args.target_port = 443
    
    print("=== HTTP Client via TCP TURN ===")
    print(f"Target: {args.target_host}:{args.target_port}")
    print(f"Protocol: {'HTTPS' if args.https else 'HTTP'}")
    print(f"TURN Server: {args.turn_server or DEFAULT_TURN_SERVER}:{args.turn_port or DEFAULT_TURN_PORT}")
    print(f"Method: {args.method}")
    print(f"Path: {args.path}")
    
    # 创建客户端
    client = HTTPTURNClient(
        target_host=args.target_host,
        target_port=args.target_port,
        use_https=args.https,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tls=args.tls
    )
    
    try:
        # 连接
        if not client.connect():
            print("[-] Failed to connect")
            return 1
            
        # 发送请求
        response = client.send_http_request(
            method=args.method,
            path=args.path,
            headers=headers,
            body=args.body
        )
        
        if response:
            print("\n=== HTTP Response ===")
            print(response)
        else:
            print("[-] No response received")
            return 1
            
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    finally:
        client.disconnect()
        
    return 0

def test_multiple_requests():
    """测试多个请求"""
    parser = argparse.ArgumentParser(description="Test multiple HTTP requests")
    parser.add_argument("--target-host", required=True, help="Target HTTP server hostname")
    parser.add_argument("--target-port", type=int, default=80, help="Target HTTP server port")
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--turn-server", help="TURN server hostname")
    parser.add_argument("--turn-port", type=int, help="TURN server port")
    parser.add_argument("--username", help="TURN server username")
    parser.add_argument("--password", help="TURN server password")
    parser.add_argument("--realm", help="TURN server realm")
    parser.add_argument("--tls", action="store_true", help="Use TLS for TURN server connection")
    
    args = parser.parse_args()
    
    # 设置默认端口
    if args.https and args.target_port == 80:
        args.target_port = 443
    
    print("=== Testing Multiple HTTP Requests ===")
    
    # 创建客户端
    client = HTTPTURNClient(
        target_host=args.target_host,
        target_port=args.target_port,
        use_https=args.https,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tls=args.tls
    )
    
    try:
        # 连接
        if not client.connect():
            print("[-] Failed to connect")
            return 1
            
        # 测试多个请求
        requests = [
            ("GET", "/", "Root path"),
            ("HEAD", "/", "HEAD request"),
            ("GET", "/status", "Status endpoint")
        ]
        
        for method, path, description in requests:
            print(f"\n=== {description} ===")
            response = client.send_http_request(method=method, path=path)
            if response:
                print(f"Response length: {len(response)} characters")
                print(f"First 200 chars: {response[:200]}...")
            else:
                print("No response received")
                
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    finally:
        client.disconnect()
        
    return 0

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        sys.argv.pop(1)  # Remove 'test' from arguments
        sys.exit(test_multiple_requests())
    else:
        sys.exit(main())