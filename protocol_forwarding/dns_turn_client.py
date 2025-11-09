"""
DNS客户端通过UDP TURN实现
使用turn_client.py中的UDP TURN功能来转发DNS查询请求
"""

import socket
import struct
import time
import argparse
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
TURN_UTILS_DIR = os.path.join(PROJECT_ROOT, "turn_utils")

for path in (PROJECT_ROOT, TURN_UTILS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from turn_utils import (
    create_permission, 
    channel_bind, 
    channel_data,
    channel_data_tcp,
    resolve_server_address
)
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

class DNSTURNClient:
    """通过UDP TURN转发DNS查询的客户端"""
    
    def __init__(self, dns_server_ip, dns_server_port=53, turn_server=None, turn_port=None, username=None, password=None, realm=None, use_tcp_udp=False, use_tls=False):
        self.dns_server_ip = dns_server_ip
        self.dns_server_port = dns_server_port
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.username = username
        self.password = password
        self.auth_realm = realm
        self.use_tcp_udp = use_tcp_udp
        self.use_tls = use_tls
        self.sock = None
        self.nonce = None
        self.realm = None
        self.integrity_key = None
        self.channel_number = 0x4000  # 通道号（必须在0x4000-0x4FFF范围内）
        self.actual_server_address = None
        self.mi_algorithm = None
        self.is_short_term = None
        
    def connect(self):
        """建立UDP TURN连接"""
        print(f"[+] Connecting to DNS server {self.dns_server_ip}:{self.dns_server_port} via TURN")
        
        # 解析TURN服务器地址
        if self.turn_server:
            server_address = resolve_server_address(self.turn_server, self.turn_port or DEFAULT_TURN_PORT)
            if not server_address:
                print("[-] Failed to resolve TURN server address")
                return False
        else:
            server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
        print(f"[+] Using TURN server: {server_address}")
        
        # 1. 分配TURN资源（带回退机制）
        if self.use_tcp_udp:
            from test_turn_capabilities import allocate_tcp_udp_with_fallback
            result, is_short_term = allocate_tcp_udp_with_fallback(
                server_address,
                self.username,
                self.password,
                self.auth_realm,
                self.turn_server,
                self.use_tls,
            )
        else:
            from test_turn_capabilities import allocate_with_fallback
            result, is_short_term = allocate_with_fallback(
                server_address,
                self.username,
                self.password,
                self.auth_realm,
                self.turn_server,
            )

        if not result:
            print("[-] Failed to allocate TURN relay")
            return False

        self.sock, self.nonce, self.realm, self.integrity_key, self.actual_server_address, *extra = result
        self.mi_algorithm = extra[0] if extra else None
        self.is_short_term = is_short_term

        if self.is_short_term:
            print("[+] TURN allocation successful (short-term credential)")
        else:
            print("[+] TURN allocation successful (long-term credential)")
        print(f"[+] Relay address: {self.actual_server_address}")
        
        # 2. 创建权限，允许向DNS服务器发送数据
        if not create_permission(self.sock, self.nonce, self.realm, self.integrity_key, 
                               self.dns_server_ip, self.dns_server_port, self.actual_server_address, self.username, self.mi_algorithm):
            print("[-] Failed to create permission")
            self.sock.close()
            return False
            
        # 3. 绑定通道
        if not channel_bind(self.sock, self.nonce, self.realm, self.integrity_key, 
                          self.dns_server_ip, self.dns_server_port, self.channel_number, self.actual_server_address, self.username, self.mi_algorithm):
            print("[-] Failed to bind channel")
            self.sock.close()
            return False
            
        print(f"[+] Channel {self.channel_number} bound successfully")
        return True
    
    def build_dns_query(self, domain, query_type=1):
        """
        构建DNS查询包
        query_type: 1=A记录, 28=AAAA记录, 15=MX记录, 2=NS记录
        """
        # DNS头部
        transaction_id = int(time.time()) & 0xFFFF
        flags = 0x0100  # 标准查询
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0
        
        header = struct.pack("!HHHHHH", transaction_id, flags, questions, 
                           answer_rrs, authority_rrs, additional_rrs)
        
        # 构建查询名称
        query_name = b""
        for part in domain.split('.'):
            query_name += struct.pack("!B", len(part)) + part.encode()
        query_name += b"\x00"  # 结束标记
        
        # 查询类型和类别
        query_type_class = struct.pack("!HH", query_type, 1)  # IN class
        
        return header + query_name + query_type_class, transaction_id
    
    def parse_dns_response(self, data):
        """解析DNS响应"""
        if len(data) < 12:
            return None
            
        # 解析头部
        transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = \
            struct.unpack("!HHHHHH", data[:12])
        
        print(f"[+] DNS Response - ID: {transaction_id}, Flags: 0x{flags:04x}")
        print(f"[+] Questions: {questions}, Answers: {answer_rrs}")
        
        # 解析问题部分
        pos = 12
        for _ in range(questions):
            # 跳过查询名称
            while pos < len(data) and data[pos] != 0:
                pos += data[pos] + 1
            pos += 5  # 跳过结束标记和类型、类别
            
        # 解析答案部分
        answers = []
        for _ in range(answer_rrs):
            if pos >= len(data):
                break
                
            # 解析名称（可能是压缩指针）
            name_start = pos
            if data[pos] & 0xC0 == 0xC0:  # 压缩指针
                pos += 2
            else:
                while pos < len(data) and data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
                
            if pos + 10 > len(data):
                break
                
            # 解析资源记录
            query_type, query_class, ttl, data_length = \
                struct.unpack("!HHIH", data[pos:pos+10])
            pos += 10
            
            if pos + data_length > len(data):
                break
                
            rdata = data[pos:pos+data_length]
            pos += data_length
            
            answers.append({
                'type': query_type,
                'class': query_class,
                'ttl': ttl,
                'data': rdata
            })
            
        return {
            'transaction_id': transaction_id,
            'flags': flags,
            'answers': answers
        }
    
    def receive_dns_response(self, timeout=5):
        """接收DNS响应"""
        try:
            self.sock.settimeout(timeout)
            if self.use_tcp_udp:
                data = self.sock.recv(1024)
            else:
                data, addr = self.sock.recvfrom(1024)
            
            # 检查是否是ChannelData消息
            if len(data) >= 4:
                channel_number = struct.unpack("!H", data[:2])[0]
                data_length = struct.unpack("!H", data[2:4])[0]
                
                if channel_number == self.channel_number and len(data) >= 4 + data_length:
                    dns_data = data[4:4+data_length]
                    return self.parse_dns_response(dns_data)
                    
        except socket.timeout:
            print("[+] No response received within timeout")
        except Exception as e:
            print(f"[-] Error receiving response: {e}")
            
        return None
    
    def query_dns(self, domain, query_type=1):
        """发送DNS查询并接收响应"""
        print(f"[+] Querying DNS for {domain} (type {query_type})")
        
        # 解析TURN服务器地址
        if self.turn_server:
            server_address = resolve_server_address(self.turn_server, self.turn_port or DEFAULT_TURN_PORT)
            if not server_address:
                print("[-] Failed to resolve TURN server address")
                return None
        else:
            server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
        # 构建DNS查询包
        query_packet, transaction_id = self.build_dns_query(domain, query_type)
        
        # 通过TURN通道发送查询
        if self.use_tcp_udp:
            if not channel_data_tcp(self.sock, self.channel_number, query_packet, self.actual_server_address):
                print("[-] Failed to send DNS query")
                return None
        else:
            if not channel_data(self.sock, self.channel_number, query_packet, self.actual_server_address):
                print("[-] Failed to send DNS query")
                return None
            
        print(f"[+] DNS query sent, waiting for response...")
        
        # 接收响应
        response = self.receive_dns_response(timeout=10)
        if response:
            print(f"[+] DNS response received:")
            print(f"    Transaction ID: {response['transaction_id']}")
            print(f"    Flags: 0x{response['flags']:04x}")
            print(f"    Answers: {len(response['answers'])}")
            
            # 解析并显示答案
            for i, answer in enumerate(response['answers']):
                print(f"    Answer {i+1}:")
                print(f"      Type: {answer['type']}")
                print(f"      TTL: {answer['ttl']}")
                
                if answer['type'] == 1:  # A记录
                    if len(answer['data']) == 4:
                        ip = socket.inet_ntoa(answer['data'])
                        print(f"      A Record: {ip}")
                elif answer['type'] == 28:  # AAAA记录
                    if len(answer['data']) == 16:
                        ipv6 = socket.inet_ntop(socket.AF_INET6, answer['data'])
                        print(f"      AAAA Record: {ipv6}")
                elif answer['type'] == 15:  # MX记录
                    print(f"      MX Record: {answer['data']}")
                elif answer['type'] == 2:  # NS记录
                    print(f"      NS Record: {answer['data']}")
                else:
                    print(f"      Data: {answer['data'].hex()}")
            
            return response
        else:
            print("[-] No DNS response received")
            return None
    
    def disconnect(self):
        """断开连接"""
        print("[+] Disconnecting...")
        if self.sock:
            self.sock.close()
        print("[+] Disconnected")

def main():
    """主函数：演示通过UDP TURN转发DNS查询"""
    import argparse
    
    parser = argparse.ArgumentParser(description='通过UDP TURN转发DNS查询')
    parser.add_argument('--dns-server', required=True, help='DNS服务器IP地址')
    parser.add_argument('--dns-port', type=int, default=53, help='DNS服务器端口 (默认: 53)')
    parser.add_argument('--turn-server', help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    parser.add_argument('--username', help='TURN服务器用户名')
    parser.add_argument('--password', help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    parser.add_argument('--domain', required=True, help='要查询的域名')
    parser.add_argument('--query-type', type=int, default=1, 
                       help='查询类型: 1=A记录, 28=AAAA记录, 15=MX记录, 2=NS记录 (默认: 1)')
    parser.add_argument('--mode', choices=['udp', 'tcp-udp'], default='udp', 
                       help='TURN模式: udp (UDP TURN), tcp-udp (TCP连接+UDP中继) (默认: udp)')
    parser.add_argument('--tls', action='store_true', help='使用TLS加密连接')
    
    args = parser.parse_args()
    
    # 确定使用的模式
    use_tcp_udp = (args.mode == 'tcp-udp')
    
    if use_tcp_udp:
        print("=== DNS Client via TCP+UDP TURN ===")
    else:
        print("=== DNS Client via UDP TURN ===")
    print(f"DNS Server: {args.dns_server}:{args.dns_port}")
    if args.turn_server:
        print(f"TURN Server: {args.turn_server}:{args.turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    print(f"Mode: {args.mode}")
    if args.tls:
        print("TLS: Enabled")
    print(f"Domain: {args.domain}")
    print(f"Query Type: {args.query_type}")
    
    # 创建DNS TURN客户端
    dns_client = DNSTURNClient(args.dns_server, args.dns_port, args.turn_server, args.turn_port, args.username, args.password, args.realm, use_tcp_udp, args.tls)
    
    try:
        # 建立连接
        if not dns_client.connect():
            print("[-] Failed to establish connection")
            return
        
        # 发送DNS查询
        transaction_id = dns_client.query_dns(args.domain, args.query_type)
        
        if transaction_id:
            print(f"[+] DNS query sent successfully (ID: {transaction_id})")
        else:
            print("[-] Failed to send DNS query")
            
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        # 清理连接
        dns_client.disconnect()

def test_multiple_queries():
    """测试多个DNS查询"""
    import argparse
    
    parser = argparse.ArgumentParser(description='测试多个DNS查询')
    parser.add_argument('--dns-server', required=True, help='DNS服务器IP地址')
    parser.add_argument('--dns-port', type=int, default=53, help='DNS服务器端口 (默认: 53)')
    parser.add_argument('--turn-server', help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    parser.add_argument('--username', help='TURN服务器用户名')
    parser.add_argument('--password', help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    
    args = parser.parse_args()
    
    print("=== Multiple DNS Queries Test via UDP TURN ===")
    print(f"DNS Server: {args.dns_server}:{args.dns_port}")
    if args.turn_server:
        print(f"TURN Server: {args.turn_server}:{args.turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    
    # 测试域名列表
    test_domains = [
        ("www.google.com", 1),      # A记录
        ("www.google.com", 28),      # AAAA记录
        ("google.com", 15),          # MX记录
        ("google.com", 2),           # NS记录
    ]
    
    # 创建DNS TURN客户端
    dns_client = DNSTURNClient(args.dns_server, args.dns_port, args.turn_server, args.turn_port, args.username, args.password, args.realm, False, False)
    
    try:
        # 建立连接
        if not dns_client.connect():
            print("[-] Failed to establish connection")
            return
        
        # 发送多个查询
        for domain, query_type in test_domains:
            print(f"\n[+] Testing query: {domain} (type {query_type})")
            transaction_id = dns_client.query_dns(domain, query_type)
            if transaction_id:
                print(f"[+] Query sent successfully (ID: {transaction_id})")
            else:
                print("[-] Query failed")
            
            # 短暂延迟
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        # 清理连接
        dns_client.disconnect()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        # 移除 "test" 参数，让 argparse 处理剩余参数
        sys.argv = sys.argv[1:]
        test_multiple_queries()
    else:
        main()
