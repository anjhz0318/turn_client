#!/usr/bin/env python3
"""
TURN 代理 TCP 扫描器

本脚本将 TURN 服务器作为代理，通过 TCP Connect 功能执行内网端口扫描。

使用方法：
python turn_tcp_port_scanner.py --turn-server <TURN服务器> --turn-port <端口> --username <用户名> --password <密码> --target <目标IP> --ports <端口范围> [--tls]
"""

import time
import socket
import struct
import argparse
import threading
import os
import sys
from typing import List, Tuple, Dict, Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))

for path in (PROJECT_ROOT, CURRENT_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)
try:
    from turn_client import (
        resolve_server_address,
        create_permission,
        tcp_connect,
        tcp_connection_bind,
    )
    from test_turn_capabilities import allocate_tcp_with_fallback
except ImportError as e:
    print(f"❌ 无法导入 TURN 工具模块: {e}")
    sys.exit(1)
class TURNScanner:
    """将TURN服务器作为代理进行TCP扫描的客户端"""
    
    def __init__(self, turn_server: str, turn_port: int, username: str, 
                 password: str, realm: str = None, use_tls: bool = False):
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls
        
        # TURN连接相关
        self.control_sock = None
        self.data_sock = None
        self.nonce = None
        self.integrity_key = None
        self.actual_server_address = None
        
        # 扫描结果
        self.scan_results = {}
        
    def connect_to_turn(self) -> bool:
        """连接到TURN服务器"""
        try:
            print(f"[+] 连接到TURN服务器 {self.turn_server}:{self.turn_port}")
            
            # 使用具备回退机制的TCP分配逻辑（参考 comprehensive_turn_tester）
            server_address = resolve_server_address(self.turn_server, self.turn_port)
            if not server_address:
                print("❌ 无法解析TURN服务器地址")
                return False
            
            result, is_short_term = allocate_tcp_with_fallback(
                server_address,
                self.username,
                self.password,
                self.realm,
                self.use_tls
            )
            
            if not result:
                print("❌ TURN分配失败")
                return False
            
            self.control_sock, self.nonce, self.realm, self.integrity_key, self.actual_server_address, *extra = result
            self.mi_algorithm = extra[0] if extra else None
            
            if is_short_term:
                print("✅ TURN连接成功 (使用短期凭证)")
            else:
                print("✅ TURN连接成功 (使用长期凭证)")
            
            print(f"   ↳ 实际服务器: {self.actual_server_address}")
            return True
                
        except Exception as e:
            print(f"❌ TURN连接异常: {e}")
            return False
    
    def scan_tcp_port_via_turn(self, target_ip: str, target_port: int) -> bool:
        """通过TURN服务器扫描单个TCP端口"""
        try:
            print(f"[+] 扫描TCP端口 {target_ip}:{target_port}")
            
            # 创建权限
            if not create_permission(
                self.control_sock, self.nonce, self.realm, self.integrity_key,
                target_ip, target_port, self.actual_server_address, self.username, self.mi_algorithm
            ):
                print(f"❌ 创建权限失败: {target_ip}:{target_port}")
                return False
            
            # 发起TCP连接
            connection_id = tcp_connect(
                self.control_sock, self.nonce, self.realm, self.integrity_key,
                target_ip, target_port, self.username, self.mi_algorithm
            )
            
            if not connection_id:
                print(f"❌ TCP连接失败: {target_ip}:{target_port}")
                return False
            
            # 建立数据连接
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.settimeout(5)
            
            try:
                data_sock.connect(self.actual_server_address)
                
                # 绑定数据连接
                if tcp_connection_bind(
                    data_sock, self.nonce, self.realm, self.integrity_key,
                    connection_id, self.actual_server_address, self.username, self.mi_algorithm
                ):
                    print(f"✅ TCP端口开放: {target_ip}:{target_port}")
                    return True
                else:
                    print(f"❌ 数据连接绑定失败: {target_ip}:{target_port}")
                    return False
                    
            except Exception as e:
                print(f"❌ 数据连接异常: {target_ip}:{target_port} - {e}")
                return False
            finally:
                data_sock.close()
                
        except Exception as e:
            print(f"❌ TCP扫描异常: {target_ip}:{target_port} - {e}")
            return False
    
    
    def scan_ports(self, target_ip: str, ports: List[int]) -> Dict[str, List[int]]:
        """扫描目标IP的多个TCP端口"""
        print(f"\n🔍 开始TCP扫描 {target_ip}")
        print(f"📋 端口列表: {ports}")
        print("="*60)
        
        open_ports = []
        closed_ports = []
        
        for port in ports:
            print(f"\n[+] 扫描端口 {port}")
            if self.scan_tcp_port_via_turn(target_ip, port):
                open_ports.append(port)
            else:
                closed_ports.append(port)
            
            # 添加延迟避免过快扫描
            time.sleep(0.5)
        
        self.scan_results[target_ip] = {
            'open': open_ports,
            'closed': closed_ports,
            'scan_type': 'tcp'
        }
        
        return self.scan_results[target_ip]
    
    def scan_with_service_detection(self, target_ip: str, ports: str) -> Dict[str, List[int]]:
        """使用TURN扫描并进行简单的服务识别"""
        print(f"\n🔍 使用TURN扫描 {target_ip} (TCP模式)")
        print(f"📋 端口范围: {ports}")
        print("="*60)
        
        try:
            # 解析端口范围
            port_list = self._parse_port_range(ports)
            print(f"[+] 扫描端口: {port_list}")
            
            # 使用TURN扫描
            results = self.scan_ports(target_ip, port_list)
            open_ports = results.get('open', [])
            
            if not open_ports:
                print("[-] 没有发现开放端口")
                return results
            
            # 对开放端口进行简单的服务识别
            print(f"[+] 对开放端口进行服务识别: {open_ports}")
            self._detect_services(target_ip, open_ports)
            
            return results
            
        except Exception as e:
            print(f"❌ 扫描异常: {e}")
            return {}
    
    def _detect_services(self, target_ip: str, open_ports: List[int]):
        """简单的服务识别"""
        service_map = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            5432: "PostgreSQL",
            3306: "MySQL",
            6379: "Redis",
            27017: "MongoDB"
        }
        
        print(f"[+] 服务识别结果:")
        for port in open_ports:
            service = service_map.get(port, "Unknown")
            print(f"    {port}/tcp: {service}")
    
    def _parse_port_range(self, ports: str) -> List[int]:
        """解析端口范围字符串"""
        port_list = []
        
        try:
            if '-' in ports:
                # 范围格式: 80-443
                start, end = map(int, ports.split('-'))
                port_list = list(range(start, end + 1))
            elif ',' in ports:
                # 逗号分隔: 80,443,8080
                port_list = [int(p.strip()) for p in ports.split(',')]
            else:
                # 单个端口
                port_list = [int(ports)]
        except ValueError:
            print(f"❌ 无效的端口格式: {ports}")
            return []
        
        return port_list
    
    def generate_report(self) -> str:
        """生成扫描报告"""
        report = "\n" + "="*60 + "\n"
        report += "📊 TURN代理扫描报告\n"
        report += "="*60 + "\n"
        
        for target_ip, results in self.scan_results.items():
            report += f"\n🎯 目标: {target_ip}\n"
            report += f"📋 扫描类型: {results['scan_type'].upper()}\n"
            report += f"✅ 开放端口: {results['open'] if results['open'] else '无'}\n"
            report += f"❌ 关闭端口: {len(results['closed'])} 个\n"
            report += "-" * 40 + "\n"
        
        return report
    
    def disconnect(self):
        """断开TURN连接"""
        if self.control_sock:
            self.control_sock.close()
            print("[+] TURN连接已断开")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='将TURN服务器作为代理进行内网扫描')
    parser.add_argument('--turn-server', required=True, help='TURN服务器地址')
    parser.add_argument('--turn-port', type=int, default=3478, help='TURN服务器端口')
    parser.add_argument('--username', required=True, help='TURN服务器用户名')
    parser.add_argument('--password', required=True, help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    parser.add_argument('--tls', action='store_true', help='使用TLS加密连接')
    parser.add_argument('--target', required=True, help='目标IP地址')
    parser.add_argument('--ports', default='80,443,8080,22,21,25,53,110,143,993,995', 
                       help='端口范围 (例如: 80-443 或 80,443,8080)')
    parser.add_argument('--detect-services', action='store_true', 
                       help='对开放端口进行服务识别')
    parser.add_argument('--output', help='输出报告到文件')
    
    args = parser.parse_args()
    
    print("🚀 TURN代理TCP扫描器")
    print("="*60)
    print(f"TURN服务器: {args.turn_server}:{args.turn_port}")
    print(f"用户名: {args.username}")
    print(f"目标: {args.target}")
    print(f"端口: {args.ports}")
    print(f"使用TLS: {args.tls}")
    print(f"服务识别: {args.detect_services}")
    
    # 创建扫描客户端
    client = TURNScanner(
        args.turn_server, args.turn_port, args.username, 
        args.password, args.realm, args.tls
    )
    
    try:
        # 连接到TURN服务器
        if not client.connect_to_turn():
            print("❌ 无法连接到TURN服务器，扫描终止")
            return
        
        # 执行扫描
        if args.detect_services:
            results = client.scan_with_service_detection(args.target, args.ports)
        else:
            port_list = client._parse_port_range(args.ports)
            results = client.scan_ports(args.target, port_list)
        
        # 生成报告
        report = client.generate_report()
        print(report)
        
        # 输出到文件
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"[+] 报告已保存到: {args.output}")
    
    except KeyboardInterrupt:
        print("\n[!] 扫描被用户中断")
    except Exception as e:
        print(f"❌ 扫描异常: {e}")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()