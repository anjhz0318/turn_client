"""
SMTP客户端通过TCP TURN实现
使用turn_client.py中的TCP TURN功能来发送SMTP邮件
"""

import socket
import time
from turn_utils import (
    allocate_tcp, 
    tcp_connect, 
    tcp_connection_bind, 
    tcp_send_data, 
    tcp_receive_data,
    resolve_server_address
)
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

class SMTPTURNClient:
    """通过TCP TURN发送SMTP邮件的客户端"""
    
    def __init__(self, smtp_server_ip, smtp_server_port=25, turn_server=None, turn_port=None):
        self.smtp_server_ip = smtp_server_ip
        self.smtp_server_port = smtp_server_port
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.control_sock = None
        self.data_sock = None
        self.nonce = None
        self.realm = None
        self.integrity_key = None
        self.connection_id = None
        
    def connect(self):
        """建立TCP TURN连接"""
        print(f"[+] Connecting to SMTP server {self.smtp_server_ip}:{self.smtp_server_port} via TURN")
        
        # 解析TURN服务器地址
        if self.turn_server:
            server_address = resolve_server_address(self.turn_server, self.turn_port or DEFAULT_TURN_PORT)
            if not server_address:
                print("[-] Failed to resolve TURN server address")
                return False
        else:
            server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
        print(f"[+] Using TURN server: {server_address}")
        
        # 1. 分配TCP TURN资源
        result = allocate_tcp(server_address)
        if not result:
            print("[-] Failed to allocate TCP TURN relay")
            return False
            
        self.control_sock, self.nonce, self.realm, self.integrity_key = result
        print("[+] TCP TURN allocation successful")
        
        # 2. 发起TCP连接到SMTP服务器
        self.connection_id = tcp_connect(
            self.control_sock, 
            self.nonce, 
            self.realm, 
            self.integrity_key, 
            self.smtp_server_ip, 
            self.smtp_server_port
        )
        
        if not self.connection_id:
            print("[-] Failed to initiate TCP connection to SMTP server")
            self.control_sock.close()
            return False
            
        print(f"[+] TCP connection initiated, connection ID: {self.connection_id}")
        
        # 3. 建立数据连接
        try:
            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_sock.settimeout(30)  # 30秒超时
            self.data_sock.connect(server_address)
            print("[+] Data connection established")
            
            # 4. 绑定数据连接到SMTP服务器连接
            if not tcp_connection_bind(
                self.data_sock, 
                self.nonce, 
                self.realm, 
                self.integrity_key, 
                self.connection_id,
                server_address
            ):
                print("[-] Failed to bind data connection")
                self.data_sock.close()
                self.control_sock.close()
                return False
                
            print("[+] Data connection bound successfully")
            return True
            
        except Exception as e:
            print(f"[-] Failed to establish data connection: {e}")
            if self.data_sock:
                self.data_sock.close()
            self.control_sock.close()
            return False
    
    def send_command(self, command):
        """发送SMTP命令并接收响应"""
        print(f"[+] Sending SMTP command: {command.decode().strip()}")
        
        if not tcp_send_data(self.data_sock, command):
            print("[-] Failed to send SMTP command")
            return None
            
        # 接收响应
        response = tcp_receive_data(self.data_sock)
        if response:
            print(f"[+] SMTP response: {response.decode().strip()}")
            return response
        else:
            print("[-] No response received")
            return None
    
    def send_email(self, from_addr, to_addr, subject, body):
        """发送邮件"""
        print(f"[+] Sending email from {from_addr} to {to_addr}")
        
        try:
            # 1. 接收服务器欢迎消息
            welcome = tcp_receive_data(self.data_sock)
            if not welcome:
                print("[-] Failed to receive welcome message")
                return False
            print(f"[+] Server welcome: {welcome.decode().strip()}")
            
            # 2. EHLO命令
            ehlo_cmd = f"EHLO turn-client.anjhz3.com\r\n".encode()
            response = self.send_command(ehlo_cmd)
            print(response.decode().strip())
            if not response or not response.startswith(b"2"):
                print("[-] EHLO failed")
                return False
            
            # 3. MAIL FROM命令
            mail_from_cmd = f"MAIL FROM: <{from_addr}>\r\n".encode()
            response = self.send_command(mail_from_cmd)
            print(response.decode().strip())
            if not response or not response.startswith(b"2"):
                print("[-] MAIL FROM failed")
                return False
            
            # 4. RCPT TO命令
            rcpt_to_cmd = f"RCPT TO: <{to_addr}>\r\n".encode()
            response = self.send_command(rcpt_to_cmd)
            print(response.decode().strip())
            if not response or not response.startswith(b"2"):
                print("[-] RCPT TO failed")
                return False
            
            # 5. DATA命令
            data_cmd = b"DATA\r\n"
            response = self.send_command(data_cmd)
            print(response.decode().strip())
            if not response or not response.startswith(b"3"):
                print("[-] DATA command failed")
                return False
            
            # 6. 发送邮件内容
            email_content = f"""From: {from_addr}
To: {to_addr}
Subject: {subject}
Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}
Content-Type: text/plain; charset=UTF-8

{body}

.
"""
            email_cmd = email_content.encode()
            response = self.send_command(email_cmd)
            if not response or not response.startswith(b"250"):
                print("[-] Email content sending failed")
                return False
            
            # 7. QUIT命令
            quit_cmd = b"QUIT\r\n"
            response = self.send_command(quit_cmd)
            if not response or not response.startswith(b"221"):
                print("[-] QUIT command failed")
                return False
            
            print("[+] Email sent successfully!")
            return True
            
        except Exception as e:
            print(f"[-] Error sending email: {e}")
            return False
    
    def disconnect(self):
        """断开连接"""
        print("[+] Disconnecting...")
        if self.data_sock:
            self.data_sock.close()
        if self.control_sock:
            self.control_sock.close()
        print("[+] Disconnected")

def main():
    """主函数：演示通过TCP TURN发送SMTP邮件"""
    import argparse
    
    parser = argparse.ArgumentParser(description='通过TCP TURN发送SMTP邮件')
    parser.add_argument('--smtp-server', required=True, help='SMTP服务器IP地址')
    parser.add_argument('--smtp-port', type=int, default=25, help='SMTP服务器端口 (默认: 25)')
    parser.add_argument('--turn-server', help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    parser.add_argument('--from-addr', required=True, help='发件人邮箱地址')
    parser.add_argument('--to-addr', required=True, help='收件人邮箱地址')
    parser.add_argument('--subject', required=True, help='邮件主题')
    parser.add_argument('--body', required=True, help='邮件正文')
    
    args = parser.parse_args()
    
    print("=== SMTP Client via TCP TURN ===")
    print(f"SMTP Server: {args.smtp_server}:{args.smtp_port}")
    if args.turn_server:
        print(f"TURN Server: {args.turn_server}:{args.turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    print(f"From: {args.from_addr}")
    print(f"To: {args.to_addr}")
    print(f"Subject: {args.subject}")
    
    # 创建SMTP TURN客户端
    smtp_client = SMTPTURNClient(args.smtp_server, args.smtp_port, args.turn_server, args.turn_port)
    
    try:
        # 建立连接
        if not smtp_client.connect():
            print("[-] Failed to establish connection")
            return
        
        # 发送邮件
        success = smtp_client.send_email(args.from_addr, args.to_addr, args.subject, args.body)
        
        if success:
            print("[+] Email sent successfully via TCP TURN!")
        else:
            print("[-] Failed to send email")
            
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        # 清理连接
        smtp_client.disconnect()

def test_simple_smtp():
    """简单的SMTP测试"""
    import argparse
    
    parser = argparse.ArgumentParser(description='简单的SMTP测试')
    parser.add_argument('--smtp-server', required=True, help='SMTP服务器IP地址')
    parser.add_argument('--smtp-port', type=int, default=25, help='SMTP服务器端口 (默认: 25)')
    parser.add_argument('--turn-server', help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    
    args = parser.parse_args()
    
    print("=== Simple SMTP Test via TCP TURN ===")
    print(f"SMTP Server: {args.smtp_server}:{args.smtp_port}")
    if args.turn_server:
        print(f"TURN Server: {args.turn_server}:{args.turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    
    # 使用指定的SMTP服务器进行测试
    smtp_client = SMTPTURNClient(args.smtp_server, args.smtp_port, args.turn_server, args.turn_port)
    
    try:
        if not smtp_client.connect():
            return
            
        # 简单的SMTP交互测试
        print("\n[+] Testing basic SMTP commands...")
        
        # 接收欢迎消息
        welcome = tcp_receive_data(smtp_client.data_sock)
        if welcome:
            print(f"[+] Welcome: {welcome.decode().strip()}")
        
        # 发送EHLO
        ehlo_response = smtp_client.send_command(b"EHLO test.anjhz3.com\r\n")
        
        # 发送QUIT
        quit_response = smtp_client.send_command(b"QUIT\r\n")
        
        print("[+] Basic SMTP test completed")
        
    except Exception as e:
        print(f"[-] Test failed: {e}")
    finally:
        smtp_client.disconnect()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_simple_smtp()
    else:
        main()
