#!/usr/bin/env python3
"""
SMTP Client via TCP TURN
支持SMTP/ESMTP协议通过TURN服务器转发
"""

import socket
import ssl
import argparse
import sys
import time
from turn_utils import (
    allocate_tcp, tcp_connection_bind, tcp_send_data, tcp_receive_data,
    resolve_server_address, resolve_peer_address, tcp_connect
)
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

class SMTPTURNClient:
    def __init__(self, target_host, target_port=25, use_tls=False, turn_server=None, turn_port=None, username=None, password=None, realm=None, use_turn_tls=False, verify_ssl=True, ssl_context=None):
        self.target_host = target_host
        self.target_port = target_port
        self.use_tls = use_tls  # 使用STARTTLS
        self.turn_server = turn_server or DEFAULT_TURN_SERVER
        self.turn_port = turn_port or DEFAULT_TURN_PORT
        self.username = username
        self.password = password
        self.realm = realm
        self.use_turn_tls = use_turn_tls
        self.verify_ssl = verify_ssl
        self.ssl_context = ssl_context
        
        self.control_sock = None
        self.data_sock = None
        self.connected = False
        self.banner = None
        
    def connect(self):
        """连接到目标SMTP服务器"""
        print(f"[+] Connecting to SMTP server {self.target_host}:{self.target_port} via TURN")
        
        # 解析TURN服务器地址
        server_address = resolve_server_address(self.turn_server, self.turn_port)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return False
            
        print(f"[+] Using TURN server: {server_address}")
        
        try:
            # 1. 分配TCP TURN中继地址
            result = allocate_tcp(server_address, self.username, self.password, self.realm, self.use_turn_tls)
            if not result:
                print("[-] Failed to allocate TCP TURN relay")
                return False
                
            self.control_sock, nonce, realm, integrity_key, actual_server_address = result
            print("[+] TCP TURN allocation successful")
            
            # 2. 发起TCP连接到对等方
            peer_ip = resolve_peer_address(self.target_host)
            if not peer_ip:
                print(f"[-] Failed to resolve peer {self.target_host}")
                self.control_sock.close()
                return False
                
            print(f"[+] Initiating TCP connection to {self.target_host}:{self.target_port}")
            print(f"[+] Resolved peer {self.target_host} to {peer_ip}")
            
            connection_id = tcp_connect(self.control_sock, nonce, realm, integrity_key, peer_ip, self.target_port, self.username)
            if not connection_id:
                print("[-] Failed to initiate TCP connection")
                self.control_sock.close()
                return False
                
            print(f"[+] Got connection ID: {connection_id}")
            
            # 3. 建立数据连接
            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_sock.settimeout(30)
            self.data_sock.connect(actual_server_address)
            print("[+] Data connection established")
            
            # 4. 绑定数据连接到对等方连接
            if not tcp_connection_bind(self.data_sock, nonce, realm, integrity_key, connection_id, actual_server_address, self.username):
                print("[-] Failed to bind data connection")
                self.data_sock.close()
                self.control_sock.close()
                return False
                
            print("[+] Data connection bound successfully")
            
            # 5. 如果是SMTP over TLS (SMTPS)，建立SSL连接
            if self.use_tls and self.target_port == 465:
                print("[+] Establishing SSL/TLS connection for SMTPS...")
                try:
                    if self.ssl_context is None:
                        context = ssl.create_default_context()
                        if not self.verify_ssl:
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            print("[+] SSL verification disabled")
                    else:
                        context = self.ssl_context
                    
                    # 包装socket为SSL socket
                    self.data_sock = context.wrap_socket(self.data_sock, server_hostname=self.target_host)
                    print("[+] SSL/TLS connection established")
                            
                except ssl.SSLError as e:
                    print(f"[-] SSL/TLS connection failed: {e}")
                    self.data_sock.close()
                    self.control_sock.close()
                    return False
                except Exception as e:
                    print(f"[-] SSL/TLS connection failed: {e}")
                    self.data_sock.close()
                    self.control_sock.close()
                    return False
            
            # 6. 接收SMTP欢迎banner
            self.banner = self._receive_line()
            if self.banner:
                print(f"[+] SMTP banner: {self.banner}")
            else:
                print("[-] No banner received")
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            if self.control_sock:
                self.control_sock.close()
            if self.data_sock:
                self.data_sock.close()
            return False
    
    def _receive_line(self):
        """接收一行SMTP响应"""
        try:
            self.data_sock.settimeout(10)
            line = self.data_sock.recv(4096)
            if line:
                return line.decode('utf-8', errors='ignore').strip()
            return None
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None
    
    def _send_command(self, command):
        """发送SMTP命令"""
        try:
            print(f"[+] Sending: {command}")
            if not tcp_send_data(self.data_sock, (command + "\r\n").encode('utf-8')):
                print("[-] Failed to send SMTP command")
                return None
            time.sleep(0.1)  # 等待响应
            return self._receive_line()
        except Exception as e:
            print(f"[-] Send command failed: {e}")
            return None
    
    def send_command(self, command):
        """发送SMTP命令并返回响应"""
        return self._send_command(command)
    
    def test_starttls(self):
        """测试STARTTLS支持"""
        print("[+] Testing STARTTLS support...")
        response = self._send_command("STARTTLS")
        if response and "220" in response:
            print("[+] STARTTLS supported")
            
            # 尝试建立TLS连接
            try:
                print("[+] Upgrading to TLS...")
                if self.ssl_context is None:
                    context = ssl.create_default_context()
                    if not self.verify_ssl:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                else:
                    context = self.ssl_context
                    
                self.data_sock = context.wrap_socket(self.data_sock, server_hostname=self.target_host)
                print("[+] TLS connection established")
                return True
            except ssl.SSLError as e:
                print(f"[-] TLS handshake failed: {e}")
                return False
        else:
            print("[-] STARTTLS not supported")
            return False
    
    def get_server_capabilities(self):
        """获取服务器能力"""
        print("[+] Retrieving server capabilities...")
        
        # 发送EHLO命令
        response = self._send_command(f"EHLO {socket.gethostname()}")
        if response:
            print(f"[+] Server response:")
            print(f"    {response}")
            
            # 继续接收多行响应
            lines = []
            while True:
                try:
                    self.data_sock.settimeout(2)
                    line = self.data_sock.recv(4096).decode('utf-8', errors='ignore').strip()
                    if not line:
                        break
                    if line.endswith(' '):  # 最后一行
                        lines.append(line.strip())
                        break
                    lines.append(line)
                    if not line.startswith('250 '):
                        break
                except socket.timeout:
                    break
                    
            for line in lines:
                print(f"    {line}")
            
            return lines
        return None
    
    def test_helo(self):
        """测试HELO命令"""
        print("[+] Testing HELO command...")
        response = self._send_command(f"HELO {socket.gethostname()}")
        if response:
            print(f"[+] HELO response: {response}")
            return response
        return None
    
    def quit(self):
        """发送QUIT命令"""
        print("[+] Sending QUIT command...")
        response = self._send_command("QUIT")
        if response:
            print(f"[+] QUIT response: {response}")
    
    def disconnect(self):
        """断开连接"""
        if self.connected:
            print("[+] Disconnecting...")
            try:
                self.quit()
            except:
                pass
            if self.data_sock:
                try:
                    if self.use_tls and hasattr(self.data_sock, 'unwrap'):
                        self.data_sock.unwrap()
                    else:
                        self.data_sock.close()
                except:
                    self.data_sock.close()
            if self.control_sock:
                self.control_sock.close()
            self.connected = False
            print("[+] Disconnected")

def main():
    parser = argparse.ArgumentParser(description="SMTP Client via TCP TURN")
    parser.add_argument("--target-host", required=True, help="Target SMTP server hostname")
    parser.add_argument("--target-port", type=int, default=25, help="Target SMTP server port (default: 25)")
    parser.add_argument("--tls", action="store_true", help="Use SMTPS (port 465) or STARTTLS")
    parser.add_argument("--turn-server", help="TURN server hostname")
    parser.add_argument("--turn-port", type=int, help="TURN server port")
    parser.add_argument("--username", help="TURN server username")
    parser.add_argument("--password", help="TURN server password")
    parser.add_argument("--realm", help="TURN server realm")
    parser.add_argument("--use-turn-tls", action="store_true", help="Use TLS for TURN server connection")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--command", help="Custom SMTP command to send")
    parser.add_argument("--get-banner", action="store_true", help="Only get SMTP banner")
    parser.add_argument("--test-starttls", action="store_true", help="Test STARTTLS support")
    parser.add_argument("--test-capabilities", action="store_true", help="Get server capabilities (EHLO)")
    
    args = parser.parse_args()
    
    print("=== SMTP Client via TCP TURN ===")
    print(f"Target: {args.target_host}:{args.target_port}")
    print(f"TURN Server: {args.turn_server or DEFAULT_TURN_SERVER}:{args.turn_port or DEFAULT_TURN_PORT}")
    
    # 创建客户端
    client = SMTPTURNClient(
        target_host=args.target_host,
        target_port=args.target_port,
        use_tls=args.tls,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_turn_tls=args.use_turn_tls,
        verify_ssl=not args.no_verify_ssl
    )
    
    try:
        # 连接
        if not client.connect():
            print("[-] Failed to connect")
            return 1
        
        # 如果只是获取banner，打印后退出
        if args.get_banner:
            return 0
        
        # 测试能力
        if args.test_capabilities:
            client.get_server_capabilities()
        
        # 测试STARTTLS
        if args.test_starttls:
            client.test_starttls()
            if client.connected:
                client.get_server_capabilities()
        
        # 测试HELO
        client.test_helo()
        
        # 发送自定义命令
        if args.command:
            response = client.send_command(args.command)
            if response:
                print(f"[+] Response: {response}")
        
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    finally:
        client.disconnect()
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
