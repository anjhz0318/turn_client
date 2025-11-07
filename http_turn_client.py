#!/usr/bin/env python3
"""
HTTP Client via TCP TURN
支持HTTP/1.1和HTTP/2请求通过TURN服务器转发
"""

import socket
import ssl
import argparse
import sys
import os
from turn_utils import (
    allocate_tcp, tcp_connection_bind, tcp_send_data, tcp_receive_data,
    resolve_server_address, resolve_peer_address, tcp_connect
)
# 导入回退机制函数和权限创建函数（参考 comprehensive_turn_tester）
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'turn_utils'))
from test_turn_capabilities import allocate_tcp_with_fallback
from turn_client import create_permission
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

class HTTPTURNClient:
    def __init__(self, target_host, target_port=80, use_https=False, turn_server=None, turn_port=None, username=None, password=None, realm=None, use_tls=False, verify_ssl=True, ssl_context=None):
        self.target_host = target_host
        self.target_port = target_port
        self.use_https = use_https
        self.turn_server = turn_server or DEFAULT_TURN_SERVER
        self.turn_port = turn_port or DEFAULT_TURN_PORT
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls
        self.verify_ssl = verify_ssl
        self.ssl_context = ssl_context
        
        self.control_sock = None
        self.data_sock = None
        self.connected = False
        self.ssl_info = None
        
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
            # 1. 分配TCP TURN中继地址（使用回退机制：先尝试长期凭据，如果400错误则回退为短期凭据）
            allocation_result, is_short_term = allocate_tcp_with_fallback(
                server_address, self.username, self.password, self.realm, self.use_tls
            )
            if not allocation_result:
                print("[-] Failed to allocate TCP TURN relay")
                return False
            
            self.control_sock, nonce, realm, integrity_key, actual_server_address, *extra = allocation_result
            mi_algorithm = extra[0] if len(extra) > 0 else None  # 可能存在 mi_algorithm
            
            if is_short_term:
                print("[+] TCP TURN allocation successful (using short-term credential)")
            else:
                print("[+] TCP TURN allocation successful (using long-term credential)")
            
            # 2. 解析对等方IP地址
            peer_ip = resolve_peer_address(self.target_host)
            if not peer_ip:
                print(f"[-] Failed to resolve peer {self.target_host}")
                self.control_sock.close()
                return False
                
            print(f"[+] Resolved peer {self.target_host} to {peer_ip}")
            
            # 3. 创建权限（参考 comprehensive_turn_tester 的处理方式）
            if not create_permission(
                self.control_sock, nonce, realm, integrity_key,
                peer_ip, self.target_port, actual_server_address, self.username, mi_algorithm
            ):
                print("[-] Failed to create permission")
                self.control_sock.close()
                return False
            
            # 4. 发起TCP连接到对等方
            print(f"[+] Initiating TCP connection to {self.target_host}:{self.target_port}")
            connection_id = tcp_connect(self.control_sock, nonce, realm, integrity_key, peer_ip, self.target_port, self.username)
            if not connection_id:
                print("[-] Failed to initiate TCP connection")
                self.control_sock.close()
                return False
                
            print(f"[+] Got connection ID: {connection_id}")
            
            # 5. 建立数据连接
            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_sock.settimeout(10)
            self.data_sock.connect(actual_server_address)
            print("[+] Data connection established")
            
            # 6. 绑定数据连接到对等方连接
            if not tcp_connection_bind(self.data_sock, nonce, realm, integrity_key, connection_id, actual_server_address, self.username):
                print("[-] Failed to bind data connection")
                self.data_sock.close()
                self.control_sock.close()
                return False
                
            print("[+] Data connection bound successfully")
            
            # 7. 如果是HTTPS，建立SSL连接
            if self.use_https:
                print("[+] Establishing SSL/TLS connection...")
                try:
                    if self.ssl_context is None:
                        context = ssl.create_default_context()
                        if not self.verify_ssl:
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            print("[+] SSL verification disabled")
                        else:
                            print("[+] SSL verification enabled")
                    else:
                        context = self.ssl_context
                    
                    # 包装socket为SSL socket
                    self.data_sock = context.wrap_socket(self.data_sock, server_hostname=self.target_host)
                    
                    # 获取SSL信息
                    self.ssl_info = {
                        'version': self.data_sock.version(),
                        'cipher': self.data_sock.cipher(),
                        'peer_cert': self.data_sock.getpeercert() if self.verify_ssl else None,
                        'compression': self.data_sock.compression(),
                        'selected_alpn_protocol': getattr(self.data_sock, 'selected_alpn_protocol', lambda: None)(),
                        'selected_npn_protocol': getattr(self.data_sock, 'selected_npn_protocol', lambda: None)()
                    }
                    
                    print("[+] SSL/TLS connection established")
                    print(f"[+] SSL version: {self.ssl_info['version']}")
                    print(f"[+] SSL cipher: {self.ssl_info['cipher']}")
                    if self.ssl_info['compression']:
                        print(f"[+] SSL compression: {self.ssl_info['compression']}")
                    if self.ssl_info['selected_alpn_protocol']:
                        print(f"[+] ALPN protocol: {self.ssl_info['selected_alpn_protocol']}")
                    if self.ssl_info['peer_cert']:
                        cert = self.ssl_info['peer_cert']
                        print(f"[+] Certificate subject: {cert.get('subject', 'Unknown')}")
                        print(f"[+] Certificate issuer: {cert.get('issuer', 'Unknown')}")
                        if 'notAfter' in cert:
                            print(f"[+] Certificate expires: {cert['notAfter']}")
                            
                except ssl.SSLError as e:
                    print(f"[-] SSL/TLS connection failed: {e}")
                    if 'certificate verify failed' in str(e):
                        print("[-] Certificate verification failed. Try --no-verify-ssl to disable verification.")
                    elif 'hostname doesn\'t match' in str(e):
                        print("[-] Hostname doesn't match certificate. Check the target hostname.")
                    self.data_sock.close()
                    self.control_sock.close()
                    return False
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
    
    def send_http_request(self, method="GET", path="/", headers=None, body=None, http_version="1.1", custom_request=None):
        """发送HTTP请求 - 支持完全自定义的HTTP请求"""
        if not self.connected:
            print("[-] Not connected")
            return None
        
        # 如果提供了自定义请求，直接使用
        if custom_request:
            request = custom_request
            print(f"[+] Sending custom HTTP request:")
            # 显示请求的前几行
            request_lines = request.split('\r\n')[:5]
            for line in request_lines:
                if line.strip():
                    print(f"    {line}")
            if len(request.split('\r\n')) > 5:
                print(f"    ... (custom request, {len(request)} chars)")
        else:
            # 构建标准HTTP请求
            if self.use_https:
                host_header = f"{self.target_host}:{self.target_port}" if self.target_port != 443 else self.target_host
            else:
                host_header = f"{self.target_host}:{self.target_port}" if self.target_port != 80 else self.target_host
            
            # 构建请求行
            request_line = f"{method} {path} HTTP/{http_version}"
            
            # 构建请求头
            request_headers = []
            request_headers.append(f"Host: {host_header}")
            
            # 添加自定义头部
            if headers:
                for key, value in headers.items():
                    request_headers.append(f"{key}: {value}")
            
            # 添加Content-Length（如果有body）
            if body:
                if isinstance(body, str):
                    body_bytes = body.encode('utf-8')
                else:
                    body_bytes = body
                request_headers.append(f"Content-Length: {len(body_bytes)}")
            
            # 构建完整请求
            request = request_line + "\r\n" + "\r\n".join(request_headers) + "\r\n\r\n"
            
            # 添加请求体
            if body:
                if isinstance(body, str):
                    request += body
                else:
                    request += body.decode('utf-8', errors='ignore')
            
            print(f"[+] Sending HTTP request:")
            print(f"    {request_line}")
            for header in request_headers:
                print(f"    {header}")
            if body:
                body_preview = str(body)[:100] + "..." if len(str(body)) > 100 else str(body)
                print(f"    Body: {body_preview}")
        
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
                        print("[!] Connection closed by server (received empty chunk)")
                        break
                    response_data += chunk
                    print(f"[+] Received {len(chunk)} bytes (total: {len(response_data)} bytes)")
                    
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
                if response_data:
                    print(f"[+] Received {len(response_data)} bytes (partial data):")
                    try:
                        # 尝试以文本形式显示
                        text_data = response_data.decode('utf-8', errors='replace')
                        print("=" * 60)
                        print(text_data)
                        print("=" * 60)
                        # 也显示原始字节（如果有特殊字符）
                        if len(response_data) <= 100:
                            print(f"[+] Raw bytes (hex): {response_data.hex()}")
                    except:
                        # 如果无法解码，显示十六进制
                        print("=" * 60)
                        print(f"Raw bytes (hex): {response_data.hex()}")
                        print("=" * 60)
                else:
                    print("[!] No data received - server may not be responding")
                return response_data if response_data else None
            
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
            # 即使出错，也返回已接收的数据
            if response_data:
                print(f"[+] Returning {len(response_data)} bytes already received")
            return response_data if response_data else None
    
    def get_ssl_info(self):
        """获取SSL连接信息"""
        return self.ssl_info
    
    @staticmethod
    def test_target(turn_server, turn_port, turn_username, turn_password, turn_realm, 
                   target_ip, target_port, use_https=False, verify_ssl=True, 
                   method="GET", path="/", headers=None, body=None, 
                   http_version="1.1", custom_request=None, use_tls=False, 
                   server_hostname=None, timeout=10):
        """
        静态方法：测试目标服务器的HTTP/HTTPS连接
        
        Args:
            turn_server: TURN服务器地址
            turn_port: TURN服务器端口
            turn_username: TURN用户名
            turn_password: TURN密码
            turn_realm: TURN认证域
            target_ip: 目标IP地址
            target_port: 目标端口
            use_https: 是否使用HTTPS
            verify_ssl: 是否验证SSL证书
            method: HTTP方法
            path: HTTP路径
            headers: HTTP头部字典
            body: 请求体
            http_version: HTTP版本
            custom_request: 自定义请求
            use_tls: TURN连接是否使用TLS
            server_hostname: TURN服务器主机名
            timeout: 超时时间
            
        Returns:
            dict: 包含测试结果的字典
        """
        client = None
        try:
            # 创建客户端
            client = HTTPTURNClient(
                target_host=target_ip,
                target_port=target_port,
                use_https=use_https,
                turn_server=turn_server,
                turn_port=turn_port,
                username=turn_username,
                password=turn_password,
                realm=turn_realm,
                use_tls=use_tls,
                verify_ssl=verify_ssl
            )
            
            # 连接
            if not client.connect():
                return {
                    'success': False,
                    'error': 'TURN connection failed',
                    'status_code': None,
                    'headers': {},
                    'content_length': 0,
                    'ssl_info': None
                }
            
            # 发送请求
            response = client.send_http_request(
                method=method,
                path=path,
                headers=headers,
                body=body,
                http_version=http_version,
                custom_request=custom_request
            )
            
            if response:
                # 解析响应
                lines = response.split('\r\n')
                status_code = None
                headers = {}
                
                # 解析状态行
                if lines and lines[0].startswith('HTTP/'):
                    try:
                        status_code = int(lines[0].split()[1])
                    except (IndexError, ValueError):
                        pass
                
                # 解析头部
                header_started = False
                for line in lines[1:]:
                    if not line:
                        header_started = True
                        break
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                
                return {
                    'success': True,
                    'error': None,
                    'status_code': status_code,
                    'headers': headers,
                    'content_length': len(response),
                    'ssl_info': client.get_ssl_info(),
                    'response': response
                }
            else:
                return {
                    'success': False,
                    'error': 'No response received',
                    'status_code': None,
                    'headers': {},
                    'content_length': 0,
                    'ssl_info': client.get_ssl_info()
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Test failed: {str(e)}',
                'status_code': None,
                'headers': {},
                'content_length': 0,
                'ssl_info': None
            }
        finally:
            if client:
                client.disconnect()
    
    def disconnect(self):
        """断开连接"""
        if self.connected:
            print("[+] Disconnecting...")
            if self.data_sock:
                try:
                    if self.use_https and hasattr(self.data_sock, 'unwrap'):
                        # 优雅关闭SSL连接
                        self.data_sock.unwrap()
                    else:
                        self.data_sock.close()
                except Exception as e:
                    print(f"[!] Warning: Error during SSL unwrap: {e}")
                    self.data_sock.close()
            if self.control_sock:
                self.control_sock.close()
            self.connected = False
            self.ssl_info = None
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
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification for HTTPS")
    parser.add_argument("--ssl-version", help="SSL version to use (e.g., TLSv1_2, TLSv1_3)")
    parser.add_argument("--ciphers", help="SSL ciphers to use (comma-separated list)")
    parser.add_argument("--alpn-protocols", help="ALPN protocols to negotiate (comma-separated list)")
    parser.add_argument("--show-cert-info", action="store_true", help="Show detailed SSL certificate information")
    parser.add_argument("--http-version", default="1.1", help="HTTP version (1.0, 1.1, 2.0) (default: 1.1)")
    parser.add_argument("--custom-request", help="Custom HTTP request (complete raw request)")
    parser.add_argument("--request-file", help="Read HTTP request from file")
    parser.add_argument("--user-agent", help="Custom User-Agent header")
    parser.add_argument("--content-type", help="Content-Type header")
    parser.add_argument("--accept", help="Accept header")
    parser.add_argument("--authorization", help="Authorization header (e.g., 'Bearer token' or 'Basic base64')")
    
    args = parser.parse_args()
    
    # 解析自定义头部
    headers = {}
    if args.headers:
        for header in args.headers.split(','):
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # 添加常用头部
    if args.user_agent:
        headers['User-Agent'] = args.user_agent
    if args.content_type:
        headers['Content-Type'] = args.content_type
    if args.accept:
        headers['Accept'] = args.accept
    if args.authorization:
        headers['Authorization'] = args.authorization
    
    # 处理自定义请求
    custom_request = None
    if args.custom_request:
        custom_request = args.custom_request
        # 将字面量 \r\n 转换为实际换行符
        custom_request = custom_request.replace('\\r\\n', '\r\n').replace('\\n', '\n')
        # 确保使用 CRLF 格式
        custom_request = custom_request.replace('\n', '\r\n').replace('\r\r\n', '\r\n')
    elif args.request_file:
        try:
            with open(args.request_file, 'r', encoding='utf-8') as f:
                custom_request = f.read()
            # 将 LF (\n) 转换为 CRLF (\r\n) 以确保HTTP格式正确
            if custom_request and '\r\n' not in custom_request:
                custom_request = custom_request.replace('\n', '\r\n')
            print(f"[+] Loaded custom request from {args.request_file}")
        except Exception as e:
            print(f"[-] Failed to read request file: {e}")
            return 1
    
    # 如果是自定义请求，也需要确保格式正确（处理可能的 LF）
    if custom_request:
        # 只处理没有 CRLF 的情况
        if '\r\n' not in custom_request and '\n' in custom_request:
            custom_request = custom_request.replace('\n', '\r\n')
    
    # 设置默认端口
    if args.https and args.target_port == 80:
        args.target_port = 443
    
    # 创建自定义SSL上下文
    ssl_context = None
    if args.https and (args.ssl_version or args.ciphers or args.alpn_protocols):
        ssl_context = ssl.create_default_context()
        
        if not args.no_verify_ssl:
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        if args.ssl_version:
            try:
                if args.ssl_version.upper() == 'TLSV1_2':
                    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                    ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
                elif args.ssl_version.upper() == 'TLSV1_3':
                    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
                    ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
                print(f"[+] Using SSL version: {args.ssl_version}")
            except AttributeError:
                print(f"[-] SSL version {args.ssl_version} not supported by this Python version")
        
        if args.ciphers:
            ssl_context.set_ciphers(args.ciphers)
            print(f"[+] Using SSL ciphers: {args.ciphers}")
        
        if args.alpn_protocols:
            protocols = [p.strip() for p in args.alpn_protocols.split(',')]
            ssl_context.set_alpn_protocols(protocols)
            print(f"[+] Using ALPN protocols: {protocols}")
    
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
        use_tls=args.tls,
        verify_ssl=not args.no_verify_ssl,
        ssl_context=ssl_context
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
            body=args.body,
            http_version=args.http_version,
            custom_request=custom_request
        )
        
        if response:
            print("\n=== HTTP Response ===")
            print(response)
            
            # 显示SSL证书信息
            if args.https and args.show_cert_info and client.get_ssl_info():
                ssl_info = client.get_ssl_info()
                if ssl_info['peer_cert']:
                    print("\n=== SSL Certificate Information ===")
                    cert = ssl_info['peer_cert']
                    print(f"Subject: {cert.get('subject', 'Unknown')}")
                    print(f"Issuer: {cert.get('issuer', 'Unknown')}")
                    print(f"Serial Number: {cert.get('serialNumber', 'Unknown')}")
                    print(f"Version: {cert.get('version', 'Unknown')}")
                    if 'notBefore' in cert:
                        print(f"Valid From: {cert['notBefore']}")
                    if 'notAfter' in cert:
                        print(f"Valid Until: {cert['notAfter']}")
                    if 'subjectAltName' in cert:
                        print(f"Subject Alternative Names: {cert['subjectAltName']}")
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
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification for HTTPS")
    
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
        use_tls=args.tls,
        verify_ssl=not args.no_verify_ssl
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