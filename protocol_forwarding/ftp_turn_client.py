#!/usr/bin/env python3
"""
FTP Client via TCP TURN
支持FTP协议通过TURN服务器转发
"""

import socket
import argparse
import sys
import re
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
TURN_UTILS_DIR = os.path.join(PROJECT_ROOT, "turn_utils")

for path in (PROJECT_ROOT, TURN_UTILS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from turn_utils import (
    allocate_tcp, tcp_connection_bind, tcp_send_data, tcp_receive_data,
    resolve_server_address, resolve_peer_address, tcp_connect
)
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

class FTPTURNClient:
    def __init__(self, ftp_host, ftp_port=21, turn_server=None, turn_port=None, turn_username=None, turn_password=None, turn_realm=None):
        self.ftp_host = ftp_host
        self.ftp_port = ftp_port
        self.turn_server = turn_server or DEFAULT_TURN_SERVER
        self.turn_port = turn_port or DEFAULT_TURN_PORT
        self.turn_username = turn_username
        self.turn_password = turn_password
        self.turn_realm = turn_realm
        
        self.control_sock = None
        self.data_sock = None
        self.connected = False
        self.passive_mode = True
        
    def connect(self):
        """连接到FTP服务器"""
        print(f"[+] Connecting to FTP server {self.ftp_host}:{self.ftp_port} via TURN")
        
        # 解析TURN服务器地址
        server_address = resolve_server_address(self.turn_server, self.turn_port)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return False
            
        print(f"[+] Using TURN server: {server_address}")
        
        try:
            # 1. 分配TCP TURN中继地址
            result = allocate_tcp(server_address, self.turn_username, self.turn_password, self.turn_realm)
            if not result:
                print("[-] Failed to allocate TCP TURN relay")
                return False
                
            self.control_sock, nonce, realm, integrity_key, actual_server_address = result
            print("[+] TCP TURN allocation successful")
            
            # 2. 发起TCP连接到FTP服务器
            peer_ip = resolve_peer_address(self.ftp_host)
            if not peer_ip:
                print(f"[-] Failed to resolve peer {self.ftp_host}")
                self.control_sock.close()
                return False
                
            print(f"[+] Initiating TCP connection to {self.ftp_host}:{self.ftp_port}")
            print(f"[+] Resolved peer {self.ftp_host} to {peer_ip}")
            
            connection_id = tcp_connect(self.control_sock, nonce, realm, integrity_key, peer_ip, self.ftp_port, self.turn_username)
            if not connection_id:
                print("[-] Failed to initiate TCP connection")
                self.control_sock.close()
                return False
                
            print(f"[+] Got connection ID: {connection_id}")
            
            # 3. 建立数据连接
            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_sock.settimeout(10)
            self.data_sock.connect(actual_server_address)
            print("[+] Data connection established")
            
            # 4. 绑定数据连接到对等方连接
            if not tcp_connection_bind(self.data_sock, nonce, realm, integrity_key, connection_id, actual_server_address, self.turn_username):
                print("[-] Failed to bind data connection")
                self.data_sock.close()
                self.control_sock.close()
                return False
                
            print("[+] Data connection bound successfully")
            
            # 5. 接收FTP欢迎消息
            welcome_msg = self._receive_response()
            if welcome_msg:
                print(f"[+] FTP Welcome: {welcome_msg.strip()}")
            
            self.connected = True
            return True
            
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            if self.control_sock:
                self.control_sock.close()
            if self.data_sock:
                self.data_sock.close()
            return False
    
    def _send_command(self, command):
        """发送FTP命令"""
        if not self.connected:
            print("[-] Not connected")
            return None
            
        print(f"[+] Sending FTP command: {command.strip()}")
        
        try:
            # 发送命令
            if not tcp_send_data(self.data_sock, command.encode('utf-8')):
                print("[-] Failed to send FTP command")
                return None
                
            # 接收响应
            response = self._receive_response()
            return response
            
        except Exception as e:
            print(f"[-] Command failed: {e}")
            return None
    
    def _receive_response(self):
        """接收FTP响应"""
        try:
            self.data_sock.settimeout(10)
            response_data = b""
            
            while True:
                chunk = self.data_sock.recv(1024)
                if not chunk:
                    break
                response_data += chunk
                
                # FTP响应以\r\n结尾
                if b"\r\n" in response_data:
                    break
                    
            if response_data:
                response = response_data.decode('utf-8', errors='ignore')
                print(f"[+] FTP Response: {response.strip()}")
                return response
            else:
                print("[-] No response received")
                return None
                
        except socket.timeout:
            print("[-] Timeout waiting for response")
            return None
        except Exception as e:
            print(f"[-] Error receiving response: {e}")
            return None
    
    def login(self, username="anonymous", password="anonymous"):
        """FTP登录"""
        if not self.connected:
            print("[-] Not connected")
            return False
            
        print(f"[+] Logging in as {username}")
        
        # USER命令
        response = self._send_command(f"USER {username}\r\n")
        if not response or not response.startswith("331"):
            print("[-] USER command failed")
            return False
            
        # PASS命令
        response = self._send_command(f"PASS {password}\r\n")
        if not response or not response.startswith("230"):
            print("[-] PASS command failed")
            return False
            
        print("[+] Login successful")
        return True
    
    def set_passive_mode(self):
        """设置被动模式"""
        response = self._send_command("PASV\r\n")
        if not response or not response.startswith("227"):
            print("[-] PASV command failed")
            return False
            
        # 解析PASV响应中的IP和端口
        # 格式: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
        match = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', response)
        if match:
            h1, h2, h3, h4, p1, p2 = map(int, match.groups())
            data_ip = f"{h1}.{h2}.{h3}.{h4}"
            data_port = p1 * 256 + p2
            print(f"[+] Passive mode: {data_ip}:{data_port}")
            return data_ip, data_port
        else:
            print("[-] Failed to parse PASV response")
            return False
    
    def list_files(self):
        """列出文件"""
        if not self.connected:
            print("[-] Not connected")
            return None
            
        print("[+] Listing files...")
        
        # 设置被动模式
        pasv_result = self.set_passive_mode()
        if pasv_result is False:
            return None
            
        data_ip, data_port = pasv_result
        
        # 建立数据连接
        data_connection = self._establish_data_connection(data_ip, data_port)
        if not data_connection:
            return None
            
        # 发送LIST命令
        response = self._send_command("LIST\r\n")
        if not response or not (response.startswith("150") or response.startswith("125")):
            print("[-] LIST command failed")
            data_connection.close()
            return None
            
        # 等待一下让服务器开始发送数据
        import time
        time.sleep(0.1)
            
        # 接收文件列表
        file_list = self._receive_data_connection(data_connection)
        data_connection.close()
        
        # 接收传输完成响应
        self._receive_response()
        
        return file_list
    
    def download_file(self, filename):
        """下载文件"""
        if not self.connected:
            print("[-] Not connected")
            return None
            
        print(f"[+] Downloading file: {filename}")
        
        # 设置被动模式
        pasv_result = self.set_passive_mode()
        if pasv_result is False:
            return None
            
        data_ip, data_port = pasv_result
        
        # 建立数据连接
        data_connection = self._establish_data_connection(data_ip, data_port)
        if not data_connection:
            return None
            
        # 发送RETR命令
        response = self._send_command(f"RETR {filename}\r\n")
        if not response or not (response.startswith("150") or response.startswith("125")):
            print("[-] RETR command failed")
            data_connection.close()
            return None
            
        # 等待一下让服务器开始发送数据
        import time
        time.sleep(0.1)
            
        # 接收文件数据
        file_data = self._receive_data_connection(data_connection)
        data_connection.close()
        
        # 接收传输完成响应
        self._receive_response()
        
        return file_data
    
    def _establish_data_connection(self, data_ip, data_port):
        """建立数据连接"""
        try:
            print(f"[+] Establishing data connection to {data_ip}:{data_port}")
            
            # 解析TURN服务器地址
            server_address = resolve_server_address(self.turn_server, self.turn_port)
            if not server_address:
                return None
                
            # 分配新的TCP TURN中继
            result = allocate_tcp(server_address, self.turn_username, self.turn_password, self.turn_realm)
            if not result:
                print("[-] Failed to allocate data TCP TURN relay")
                return None
                
            control_sock, nonce, realm, integrity_key, actual_server_address = result
            
            # 连接到FTP数据端口
            peer_ip = resolve_peer_address(data_ip)
            if not peer_ip:
                print(f"[-] Failed to resolve data peer {data_ip}")
                control_sock.close()
                return None
                
            connection_id = tcp_connect(control_sock, nonce, realm, integrity_key, peer_ip, data_port, self.turn_username)
            if not connection_id:
                print("[-] Failed to initiate data TCP connection")
                control_sock.close()
                return None
                
            # 建立数据连接
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.settimeout(30)
            data_sock.connect(actual_server_address)
            
            # 绑定数据连接
            if not tcp_connection_bind(data_sock, nonce, realm, integrity_key, connection_id, actual_server_address, self.turn_username):
                print("[-] Failed to bind data connection")
                data_sock.close()
                control_sock.close()
                return None
                
            print("[+] Data connection established successfully")
            
            # 关闭控制连接，只保留数据连接
            control_sock.close()
            
            return data_sock
            
        except Exception as e:
            print(f"[-] Data connection failed: {e}")
            return None
    
    def _receive_data_connection(self, data_sock):
        """从数据连接接收数据"""
        try:
            data_sock.settimeout(10)
            data = b""
            
            # 设置非阻塞模式，避免长时间等待
            data_sock.settimeout(5)
            
            while True:
                try:
                    chunk = data_sock.recv(4096)
                    if not chunk:
                        print("[+] Data connection closed by server")
                        break
                    data += chunk
                    print(f"[+] Received {len(chunk)} bytes")
                    
                except socket.timeout:
                    print("[+] Timeout waiting for more data, assuming transfer complete")
                    break
                except ConnectionResetError:
                    print("[+] Connection reset by server, assuming transfer complete")
                    break
                    
            print(f"[+] Total received: {len(data)} bytes")
            return data
            
        except Exception as e:
            print(f"[-] Error receiving data: {e}")
            return b""
    
    def disconnect(self):
        """断开连接"""
        if self.connected:
            print("[+] Disconnecting...")
            self._send_command("QUIT\r\n")
            if self.data_sock:
                self.data_sock.close()
            if self.control_sock:
                self.control_sock.close()
            self.connected = False
            print("[+] Disconnected")

def main():
    parser = argparse.ArgumentParser(description="FTP Client via TCP TURN")
    parser.add_argument("--ftp-host", required=True, help="FTP server hostname")
    parser.add_argument("--ftp-port", type=int, default=21, help="FTP server port")
    parser.add_argument("--username", default="anonymous", help="FTP username")
    parser.add_argument("--password", default="anonymous", help="FTP password")
    parser.add_argument("--command", help="FTP command to execute")
    parser.add_argument("--list", action="store_true", help="List files")
    parser.add_argument("--download", help="Download file")
    parser.add_argument("--turn-server", help="TURN server hostname")
    parser.add_argument("--turn-port", type=int, help="TURN server port")
    parser.add_argument("--turn-username", help="TURN server username")
    parser.add_argument("--turn-password", help="TURN server password")
    parser.add_argument("--turn-realm", help="TURN server realm")
    
    args = parser.parse_args()
    
    print("=== FTP Client via TCP TURN ===")
    print(f"FTP Server: {args.ftp_host}:{args.ftp_port}")
    print(f"TURN Server: {args.turn_server or DEFAULT_TURN_SERVER}:{args.turn_port or DEFAULT_TURN_PORT}")
    print(f"Username: {args.username}")
    
    # 创建客户端
    client = FTPTURNClient(
        ftp_host=args.ftp_host,
        ftp_port=args.ftp_port,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        turn_username=args.turn_username,
        turn_password=args.turn_password,
        turn_realm=args.turn_realm
    )
    
    try:
        # 连接
        if not client.connect():
            print("[-] Failed to connect")
            return 1
            
        # 登录
        if not client.login(args.username, args.password):
            print("[-] Login failed")
            return 1
            
        # 执行命令
        if args.list:
            file_list = client.list_files()
            if file_list:
                print("\n=== File List ===")
                print(file_list.decode('utf-8', errors='ignore'))
            else:
                print("[-] Failed to list files")
                
        elif args.download:
            file_data = client.download_file(args.download)
            if file_data:
                print(f"\n=== Downloaded {args.download} ===")
                print(f"Size: {len(file_data)} bytes")
                print(f"Content preview: {file_data[:200]}...")
            else:
                print("[-] Failed to download file")
                
        elif args.command:
            response = client._send_command(f"{args.command}\r\n")
            if response:
                print(f"\n=== Command Response ===")
                print(response)
            else:
                print("[-] Command failed")
                
        else:
            print("[+] Connected successfully. Use --list, --download, or --command to interact with FTP server")
            
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    finally:
        client.disconnect()
        
    return 0

def test_rebex_ftp():
    """测试Rebex FTP服务器"""
    parser = argparse.ArgumentParser(description="Test Rebex FTP server")
    parser.add_argument("--turn-server", help="TURN server hostname")
    parser.add_argument("--turn-port", type=int, help="TURN server port")
    
    args = parser.parse_args()
    
    print("=== Testing Rebex FTP Server ===")
    
    # 创建客户端
    client = FTPTURNClient(
        ftp_host="test.rebex.net",
        ftp_port=21,
        turn_server=args.turn_server,
        turn_port=args.turn_port
    )
    
    try:
        # 连接
        if not client.connect():
            print("[-] Failed to connect")
            return 1
            
        # 登录
        if not client.login("demo", "password"):
            print("[-] Login failed")
            return 1
            
        # 列出文件
        file_list = client.list_files()
        if file_list:
            print("\n=== File List ===")
            print(file_list.decode('utf-8', errors='ignore'))
        else:
            print("[-] Failed to list files")
            
        # 下载readme.txt
        file_data = client.download_file("readme.txt")
        if file_data:
            print(f"\n=== Downloaded readme.txt ===")
            print(file_data.decode('utf-8', errors='ignore'))
        else:
            print("[-] Failed to download readme.txt")
            
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    finally:
        client.disconnect()
        
    return 0

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        sys.argv.pop(1)  # Remove 'test' from arguments
        sys.exit(test_rebex_ftp())
    else:
        sys.exit(main())
