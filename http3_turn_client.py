"""
HTTP/3客户端通过UDP TURN实现
使用QUIC协议进行HTTP/3通信
"""

import socket
import struct
import time
import argparse
from turn_client import (
    allocate, 
    create_permission, 
    channel_bind, 
    channel_data,
    resolve_server_address
)
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

class HTTP3TURNClient:
    """通过UDP TURN转发HTTP/3请求的客户端"""
    
    def __init__(self, target_host, target_port=443, turn_server=None, turn_port=None):
        self.target_host = target_host
        self.target_port = target_port
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.sock = None
        self.nonce = None
        self.realm = None
        self.integrity_key = None
        self.channel_number = 0x4000  # 通道号（必须在0x4000-0x4FFF范围内）
        
    def connect(self):
        """建立UDP TURN连接"""
        print(f"[+] Connecting to HTTP/3 server {self.target_host}:{self.target_port} via TURN")
        
        # 解析TURN服务器地址
        if self.turn_server:
            server_address = resolve_server_address(self.turn_server, self.turn_port or DEFAULT_TURN_PORT)
            if not server_address:
                print("[-] Failed to resolve TURN server address")
                return False
        else:
            server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
        print(f"[+] Using TURN server: {server_address}")
        
        # 1. 分配UDP TURN资源
        result = allocate(server_address)
        if not result:
            print("[-] Failed to allocate UDP TURN relay")
            return False
            
        self.sock, self.nonce, self.realm, self.integrity_key = result
        print("[+] UDP TURN allocation successful")
        
        # 2. 创建权限，允许向HTTP/3服务器发送数据
        if not create_permission(self.sock, self.nonce, self.realm, self.integrity_key, 
                               self.target_host, self.target_port, server_address):
            print("[-] Failed to create permission")
            self.sock.close()
            return False
            
        # 3. 绑定通道
        if not channel_bind(self.sock, self.nonce, self.realm, self.integrity_key, 
                          self.target_host, self.target_port, self.channel_number, server_address):
            print("[-] Failed to bind channel")
            self.sock.close()
            return False
            
        print(f"[+] Channel {self.channel_number} bound successfully")
        return True
    
    def build_quic_initial_packet(self):
        """构建QUIC Initial包"""
        # 这是一个简化的QUIC Initial包实现
        # 实际实现需要完整的QUIC协议栈
        
        # QUIC Header (简化版)
        # Version: 1 (QUIC v1)
        version = 1
        
        # Destination Connection ID (8 bytes)
        dcid = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        
        # Source Connection ID (8 bytes)  
        scid = b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        
        # Token Length (变长整数)
        token_length = 0
        
        # Length (变长整数) - 会在后面计算
        length = 0
        
        # Packet Number (1 byte for Initial)
        packet_number = 1
        
        # 构建头部
        header = struct.pack('>I', version)  # Version
        header += struct.pack('B', len(dcid))  # DCID Length
        header += dcid  # Destination Connection ID
        header += struct.pack('B', len(scid))  # SCID Length  
        header += scid  # Source Connection ID
        header += struct.pack('B', token_length)  # Token Length
        header += struct.pack('B', length)  # Length (占位符)
        header += struct.pack('B', packet_number)  # Packet Number
        
        # CRYPTO帧 (包含TLS ClientHello)
        crypto_frame = self._build_crypto_frame()
        
        # 计算总长度
        total_length = len(crypto_frame)
        
        # 更新长度字段
        header = header[:-2] + struct.pack('B', total_length) + header[-1:]
        
        return header + crypto_frame
    
    def _build_crypto_frame(self):
        """构建CRYPTO帧"""
        # CRYPTO帧格式: Type(1) + Offset(变长) + Length(变长) + Crypto Data
        
        # 简化的TLS ClientHello (实际需要完整的TLS实现)
        tls_client_hello = self._build_tls_client_hello()
        
        # CRYPTO帧
        frame_type = 0x06  # CRYPTO
        offset = 0
        length = len(tls_client_hello)
        
        # 构建变长整数编码
        def encode_varint(value):
            if value < 0x40:
                return struct.pack('B', value)
            elif value < 0x4000:
                return struct.pack('>H', value | 0x4000)
            elif value < 0x40000000:
                return struct.pack('>I', value | 0x80000000)
            else:
                return struct.pack('>Q', value | 0xc000000000000000)
        
        frame = struct.pack('B', frame_type)
        frame += encode_varint(offset)
        frame += encode_varint(length)
        frame += tls_client_hello
        
        return frame
    
    def _build_tls_client_hello(self):
        """构建TLS ClientHello消息"""
        # 这是一个极简的TLS ClientHello实现
        # 实际应用中需要使用完整的TLS库
        
        # TLS Record Header
        content_type = 0x16  # Handshake
        version = 0x0303  # TLS 1.2
        length = 0  # 将在后面设置
        
        # Handshake Header
        handshake_type = 0x01  # ClientHello
        handshake_length = 0  # 将在后面设置
        
        # ClientHello内容
        client_version = 0x0303  # TLS 1.2
        random = b'\x00' * 32  # Random (简化)
        session_id_length = 0
        cipher_suites_length = 2
        cipher_suite = 0x1301  # TLS_AES_128_GCM_SHA256
        compression_methods_length = 1
        compression_method = 0x00  # NULL
        extensions_length = 0
        
        # 构建ClientHello
        client_hello = struct.pack('>H', client_version)  # Client Version
        client_hello += random  # Random
        client_hello += struct.pack('B', session_id_length)  # Session ID Length
        client_hello += struct.pack('>H', cipher_suites_length)  # Cipher Suites Length
        client_hello += struct.pack('>H', cipher_suite)  # Cipher Suite
        client_hello += struct.pack('B', compression_methods_length)  # Compression Methods Length
        client_hello += struct.pack('B', compression_method)  # Compression Method
        client_hello += struct.pack('>H', extensions_length)  # Extensions Length
        
        # 构建Handshake
        handshake = struct.pack('B', handshake_type)  # Handshake Type
        handshake += struct.pack('>I', len(client_hello))[1:]  # Handshake Length (3 bytes)
        handshake += client_hello
        
        # 构建TLS Record
        record = struct.pack('B', content_type)  # Content Type
        record += struct.pack('>H', version)  # Version
        record += struct.pack('>H', len(handshake))  # Length
        record += handshake
        
        return record
    
    def send_http3_request(self, method="GET", path="/", headers=None):
        """发送HTTP/3请求"""
        if headers is None:
            headers = {}
            
        print(f"[+] Sending HTTP/3 request: {method} {path}")
        
        # 构建HTTP/3请求帧
        # 这里使用简化的实现，实际需要完整的HTTP/3和QUIC协议栈
        
        # 构建HTTP/3请求
        request_lines = []
        request_lines.append(f"{method} {path} HTTP/3")
        request_lines.append(f"Host: {self.target_host}")
        
        for key, value in headers.items():
            request_lines.append(f"{key}: {value}")
            
        request_text = "\r\n".join(request_lines) + "\r\n\r\n"
        request_bytes = request_text.encode('utf-8')
        
        # 构建QUIC包
        quic_packet = self.build_quic_initial_packet()
        
        # 将HTTP/3请求添加到QUIC包中
        # 这里简化处理，实际需要正确的QUIC帧格式
        full_packet = quic_packet + request_bytes
        
        # 通过TURN通道发送
        server_address = (self.turn_server or DEFAULT_TURN_SERVER, self.turn_port or DEFAULT_TURN_PORT)
        if not channel_data(self.sock, self.channel_number, full_packet, server_address):
            print("[-] Failed to send HTTP/3 request")
            return None
            
        print("[+] HTTP/3 request sent successfully")
        
        # 接收响应
        response = self._receive_http3_response()
        return response
    
    def _receive_http3_response(self):
        """接收HTTP/3响应"""
        print("[+] Waiting for HTTP/3 response...")
        
        try:
            self.sock.settimeout(10)
            data, addr = self.sock.recvfrom(4096)
            
            # 检查是否是ChannelData消息
            if len(data) >= 4:
                channel_number = struct.unpack("!H", data[:2])[0]
                data_length = struct.unpack("!H", data[2:4])[0]
                
                if channel_number == self.channel_number and len(data) >= 4 + data_length:
                    response_data = data[4:4+data_length]
                    
                    # 解析QUIC响应（简化）
                    # 实际需要完整的QUIC协议解析
                    print(f"[+] HTTP/3 response received ({len(response_data)} bytes)")
                    
                    # 尝试提取HTTP响应
                    try:
                        response_text = response_data.decode('utf-8', errors='ignore')
                        return self._parse_http3_response(response_text)
                    except:
                        return {"raw_data": response_data.hex()}
                        
        except socket.timeout:
            print("[+] No response received within timeout")
        except Exception as e:
            print(f"[-] Error receiving response: {e}")
            
        return None
    
    def _parse_http3_response(self, response_text):
        """解析HTTP/3响应"""
        try:
            lines = response_text.split('\r\n')
            if not lines:
                return {"error": "Empty response"}
                
            # 解析状态行
            status_line = lines[0]
            parts = status_line.split(' ', 2)
            
            if len(parts) >= 2:
                protocol_version = parts[0]
                status_code = parts[1]
                status_message = parts[2] if len(parts) > 2 else ""
            else:
                return {"error": "Invalid status line"}
            
            # 解析头部
            headers = {}
            body_start = 1
            
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # 提取主体
            body_lines = lines[body_start:]
            body = '\r\n'.join(body_lines)
            
            return {
                "protocol_version": protocol_version,
                "status_code": status_code,
                "status_message": status_message,
                "headers": headers,
                "body": body
            }
            
        except Exception as e:
            print(f"[-] Error parsing HTTP/3 response: {e}")
            return {"error": f"Parse error: {e}"}
    
    def disconnect(self):
        """断开连接"""
        print("[+] Disconnecting...")
        if self.sock:
            self.sock.close()
        print("[+] Disconnected")

def main():
    """主函数：演示通过UDP TURN发送HTTP/3请求"""
    import argparse
    
    parser = argparse.ArgumentParser(description='通过UDP TURN发送HTTP/3请求')
    parser.add_argument('--target-host', required=True, help='目标HTTP/3服务器主机名或IP')
    parser.add_argument('--target-port', type=int, default=443, help='目标HTTP/3服务器端口 (默认: 443)')
    parser.add_argument('--turn-server', help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    parser.add_argument('--method', default='GET', help='HTTP方法 (默认: GET)')
    parser.add_argument('--path', default='/', help='请求路径 (默认: /)')
    parser.add_argument('--header', action='append', help='HTTP头部 (格式: Key: Value)')
    parser.add_argument('--output', help='将响应保存到文件')
    
    args = parser.parse_args()
    
    print("=== HTTP/3 Client via UDP TURN ===")
    print(f"Target: {args.target_host}:{args.target_port}")
    print(f"Protocol: HTTP/3 (QUIC)")
    if args.turn_server:
        print(f"TURN Server: {args.turn_server}:{args.turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    print(f"Method: {args.method}")
    print(f"Path: {args.path}")
    
    # 创建HTTP/3 TURN客户端
    http3_client = HTTP3TURNClient(
        args.target_host, 
        args.target_port, 
        args.turn_server, 
        args.turn_port
    )
    
    try:
        # 建立连接
        if not http3_client.connect():
            print("[-] Failed to establish connection")
            return
        
        # 解析头部
        headers = {}
        if args.header:
            for header in args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # 发送HTTP/3请求
        response = http3_client.send_http3_request(
            method=args.method,
            path=args.path,
            headers=headers
        )
        
        if response:
            print(f"\n[+] HTTP/3 Response:")
            if 'error' in response:
                print(f"    Error: {response['error']}")
            else:
                print(f"    Status: {response.get('status_code', 'Unknown')} {response.get('status_message', '')}")
                print(f"    Protocol: {response.get('protocol_version', 'Unknown')}")
                
                # 显示头部
                print(f"\n[+] Response Headers:")
                for key, value in response.get('headers', {}).items():
                    print(f"    {key}: {value}")
                
                # 显示响应体
                body = response.get('body', '')
                if body:
                    print(f"\n[+] Response Body ({len(body)} bytes):")
                    # 限制显示长度
                    if len(body) > 1000:
                        print(f"    {body[:1000]}...")
                    else:
                        print(f"    {body}")
                
                # 保存到文件
                if args.output:
                    try:
                        with open(args.output, 'w', encoding='utf-8') as f:
                            f.write(body)
                        print(f"\n[+] Response saved to {args.output}")
                    except Exception as e:
                        print(f"[-] Failed to save response: {e}")
        else:
            print("[-] Failed to get HTTP/3 response")
            
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        # 清理连接
        http3_client.disconnect()

def test_http3_connection():
    """测试HTTP/3连接"""
    import argparse
    
    parser = argparse.ArgumentParser(description='测试HTTP/3连接')
    parser.add_argument('--target-host', required=True, help='目标HTTP/3服务器主机名或IP')
    parser.add_argument('--target-port', type=int, default=443, help='目标HTTP/3服务器端口 (默认: 443)')
    parser.add_argument('--turn-server', help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    
    args = parser.parse_args()
    
    print("=== HTTP/3 Connection Test via UDP TURN ===")
    print(f"Target: {args.target_host}:{args.target_port}")
    print(f"Protocol: HTTP/3 (QUIC)")
    if args.turn_server:
        print(f"TURN Server: {args.turn_server}:{args.turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    
    # 创建HTTP/3 TURN客户端
    http3_client = HTTP3TURNClient(
        args.target_host, 
        args.target_port, 
        args.turn_server, 
        args.turn_port
    )
    
    try:
        # 建立连接
        if not http3_client.connect():
            print("[-] Failed to establish connection")
            return
        
        print("[+] HTTP/3 connection established successfully")
        print("[+] Note: This is a simplified HTTP/3 implementation")
        print("[+] For production use, a full QUIC protocol stack is required")
        
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        # 清理连接
        http3_client.disconnect()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        # 移除 "test" 参数，让 argparse 处理剩余参数
        sys.argv = sys.argv[1:]
        test_http3_connection()
    else:
        main()
