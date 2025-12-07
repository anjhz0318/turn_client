#!/usr/bin/env python3
"""
综合性UDP TURN服务器测试脚本
支持UDP和TCP+UDP allocation测试、UDP端口扫描和协议探测
"""

import argparse
import json
import os
import sys
import threading
import time
from typing import Dict, List, Tuple, Set, Optional
from datetime import datetime
import queue
import socket
import struct

# 导入TURN相关模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'turn_utils'))
from turn_server_discovery import TURNServerDiscovery
from test_turn_capabilities import test_udp_turn, test_tcp_udp_turn, allocate_with_fallback, allocate_tcp_udp_with_fallback
from turn_client import create_permission, channel_bind, channel_data, channel_data_tcp, resolve_server_address, parse_attrs, STUN_MAGIC_COOKIE
from turn_udp_port_scanner import scan_udp_port, send_udp_packet, receive_icmp_error, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, STUN_DATA_INDICATION, STUN_ATTR_ICMP
from turn_client import STUN_ATTR_XOR_PEER_ADDRESS

# 导入UDP协议数据包
sys.path.insert(0, os.path.dirname(__file__))
from udp_protocol_packets import UDP_PROTOCOL_PACKETS, get_protocol_packet, get_all_protocols, get_protocols_for_port


class ComprehensiveUDPTURNTester:
    """综合性UDP TURN服务器测试器"""
    
    def __init__(self, turn_server: str, turn_port: int, username: str, 
                 password: str, realm: str = None, use_tls: bool = False,
                 output_file: str = "turn_udp_test_results.json", 
                 ip_file: Optional[str] = None, port_file: Optional[str] = None):
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.username = username
        self.password = password
        self.realm = realm or "default"
        self.use_tls = use_tls
        self.output_file = output_file
        self.ip_file = ip_file
        self.port_file = port_file
        
        # 初始化发现工具
        self.discovery = TURNServerDiscovery()
        
        # 加载测试目标
        self.test_ips = self._load_test_ips()
        self.test_ports = self._load_test_ports()
        
        # 初始化结果存储
        self.results = self._load_or_init_results()
        self.lock = threading.Lock()
        
    def _load_test_ips(self) -> List[str]:
        """加载测试IP列表"""
        try:
            ip_file = self.ip_file or 'standard_test_ips.txt'
            with open(ip_file, 'r', encoding="utf-8") as f:
                ips = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                print(f"[+] 使用测试IP文件: {ip_file}（共 {len(ips)} 条）")
                return ips
        except FileNotFoundError:
            if self.ip_file:
                print(f"[-] 指定的IP文件 {self.ip_file} 未找到，使用默认IP列表")
            else:
                print("[-] standard_test_ips.txt not found, using default IPs")
            return ['192.168.1.1', '172.16.0.1']
    
    def _load_test_ports(self) -> List[int]:
        """加载测试端口列表"""
        try:
            port_file = self.port_file or 'standard_test_ports.txt'
            with open(port_file, 'r', encoding="utf-8") as f:
                ports = [int(line.strip()) for line in f if line.strip() and not line.strip().startswith('#')]
                print(f"[+] 使用测试端口文件: {port_file}（共 {len(ports)} 条）")
                return ports
        except FileNotFoundError:
            if self.port_file:
                print(f"[-] 指定的端口文件 {self.port_file} 未找到，使用默认端口列表")
            else:
                print("[-] standard_test_ports.txt not found, using default ports")
            return [53, 67, 161, 123]
    
    def _load_or_init_results(self) -> Dict:
        """加载已有结果或初始化新结果"""
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    data = json.load(f)
                    print(f"[+] 加载已存在的结果文件: {self.output_file}")
                    
                    # 检查新的格式
                    if self.turn_server in data:
                        tested_count = sum(
                            len(server_data.get('tested_targets', {})) 
                            for server_data in data[self.turn_server].values()
                        )
                        print(f"[+] 已测试内容: {tested_count} 个目标")
                        return data
                    else:
                        # 兼容旧格式
                        tested_count = len(data.get('tested_targets', {}))
                        print(f"[+] 已测试内容: {tested_count} 个目标")
                        return data
            except Exception as e:
                print(f"[-] 无法加载结果文件: {e}")
        
        # 返回新格式
        return {
            self.turn_server: {}
        }
    
    def _save_results(self):
        """保存结果到文件（实时更新）"""
        try:
            with self.lock:
                # 直接保存 self.results，因为它已经在内存中维护了完整状态
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=2)
        except Exception as e:
            print(f"[-] 保存结果失败: {e}")
    
    def discover_server_ips(self) -> List[str]:
        """发现TURN服务器的所有IP"""
        print(f"[+] 开始发现TURN服务器IP: {self.turn_server}")
        try:
            ips = self.discovery.discover_all_ips(self.turn_server, max_queries=50)
            ip_list = list(ips)
            
            # 初始化每个IP的结构
            if self.turn_server not in self.results:
                self.results[self.turn_server] = {}
            
            for ip in ip_list:
                if ip not in self.results[self.turn_server]:
                    self.results[self.turn_server][ip] = {
                        'metadata': {
                            'turn_port': self.turn_port,
                            'username': self.username,
                            'discovery_timestamp': datetime.now().isoformat()
                        },
                        'capabilities': {},
                        'tested_targets': {}
                    }
            
            self._save_results()
            print(f"[+] 发现 {len(ip_list)} 个TURN服务器IP")
            return ip_list
        except Exception as e:
            print(f"[-] DNS发现失败: {e}")
            return []
    
    def test_capabilities(self, server_ip: str) -> Dict:
        """测试TURN服务器能力（只测试UDP和TCP+UDP）"""
        print(f"\n[+] 测试服务器能力: {server_ip}")
        
        server_address = (server_ip, self.turn_port)
        capabilities = {}
        
        # 测试UDP（使用回退机制）
        print("  [1/2] 测试UDP TURN...")
        try:
            test_ip = "8.8.8.8"
            test_port = 53
            result = test_udp_turn(
                server_address, self.username, self.password, 
                self.realm, self.turn_server, test_ip, test_port, False
            )
            capabilities['udp'] = result
        except Exception as e:
            print(f"  [-] UDP测试失败: {e}")
            capabilities['udp'] = False
        
        # 测试TCP+UDP（使用回退机制）
        print("  [2/2] 测试TCP+UDP TURN...")
        try:
            test_ip = "8.8.8.8"
            test_port = 53
            result = test_tcp_udp_turn(
                server_address, self.username, self.password, 
                self.realm, self.turn_server, self.use_tls, test_ip, test_port, False
            )
            capabilities['tcp_udp'] = result
        except Exception as e:
            print(f"  [-] TCP+UDP测试失败: {e}")
            capabilities['tcp_udp'] = False
        
        # 保存能力测试结果
        if self.turn_server in self.results and server_ip in self.results[self.turn_server]:
            self.results[self.turn_server][server_ip]['capabilities'] = capabilities
            self._save_results()
        
        return capabilities
    
    def test_internal_network_access(self, server_ip: str, target_ip: str):
        """测试内网IP的UDP转发能力"""
        print(f"\n[+] 测试内网IP转发: {target_ip}")
        
        # 初始化结构
        if self.turn_server not in self.results:
            self.results[self.turn_server] = {}
        if server_ip not in self.results[self.turn_server]:
            self.results[self.turn_server][server_ip] = {
                'metadata': {'turn_port': self.turn_port, 'username': self.username},
                'capabilities': {},
                'tested_targets': {}
            }
        
        if 'tested_targets' not in self.results[self.turn_server][server_ip]:
            self.results[self.turn_server][server_ip]['tested_targets'] = {}
        
        if target_ip not in self.results[self.turn_server][server_ip]['tested_targets']:
            self.results[self.turn_server][server_ip]['tested_targets'][target_ip] = {
                'ports': {},
                'timestamp': datetime.now().isoformat()
            }
        
        # 测试所有端口
        for i, port in enumerate(self.test_ports, 1):
            print(f"  [{i}/{len(self.test_ports)}] 测试端口{port}...")
            
            result = self._test_port(server_ip, target_ip, port)
            
            self.results[self.turn_server][server_ip]['tested_targets'][target_ip]['ports'][str(port)] = result
            self._save_results()
            
            # 如果权限被拒绝，跳过后续端口和整个IP
            if result.get('permission_denied', False):
                print(f"  [-] IP {target_ip} 权限被拒绝，跳过后续端口和整个IP")
                self.results[self.turn_server][server_ip]['tested_targets'][target_ip]['permission_denied'] = True
                return  # 直接返回，跳过整个IP的所有端口
    
    def _test_port(self, server_ip: str, target_ip: str, target_port: int) -> Dict:
        """测试特定端口的UDP转发能力和协议探测"""
        result = {
            'port': target_port,
            'timestamp': datetime.now().isoformat(),
            'permission_denied': False,
            'port_status': None,
            'protocols_tested': {},
            'error': None
        }
        
        try:
            # 1. 先扫描端口状态
            print(f"    [*] 扫描端口状态...")
            port_status = scan_udp_port(
                self.turn_server, self.turn_port, self.username, self.password,
                self.realm, target_ip, target_port, timeout=3, use_tls=self.use_tls
            )
            result['port_status'] = port_status
            
            if port_status == "error":
                # 检查是否是权限被拒绝导致的错误
                # 尝试创建一个权限来确认
                if self._check_permission_denied(server_ip, target_ip, target_port):
                    result['permission_denied'] = True
                    result['error'] = 'Permission denied'
                    print(f"    [-] 权限被拒绝：无法访问 {target_ip}:{target_port}")
                    return result
                else:
                    result['error'] = 'Port scan failed'
                    return result
            
            if port_status == "closed":
                print(f"    [+] 端口 {target_port} 已关闭，跳过协议探测")
                return result
            
            # 2. 如果端口是 open|filtered，尝试协议探测
            if port_status in ["open|filtered", "open", "filtered"]:
                print(f"    [*] 端口 {target_port} 状态: {port_status}，开始协议探测...")
                
                # 获取该端口可能的协议
                port_protocols = get_protocols_for_port(target_port)
                # 如果没有特定协议，尝试所有协议
                if not port_protocols:
                    port_protocols = get_all_protocols()
                
                # 测试每个协议
                for protocol_name in port_protocols:
                    protocol_result = self._test_protocol(server_ip, target_ip, target_port, protocol_name)
                    result['protocols_tested'][protocol_name] = protocol_result
                    
                    # 如果遇到权限被拒绝，设置标志并返回
                    if protocol_result.get('permission_denied', False):
                        result['permission_denied'] = True
                        result['error'] = 'Permission denied'
                        print(f"    [-] 权限被拒绝，停止协议探测")
                        return result
                    
                    # 如果某个协议有响应，记录并继续测试其他协议
                    if protocol_result.get('has_response', False):
                        print(f"    [+] 协议 {protocol_name} 有响应！")
        
        except Exception as e:
            result['error'] = str(e)
            import traceback
            traceback.print_exc()
        
        return result
    
    def _check_permission_denied(self, server_ip: str, target_ip: str, target_port: int) -> bool:
        """检查是否是权限被拒绝导致的错误"""
        try:
            server_address = resolve_server_address(self.turn_server, self.turn_port)
            if not server_address:
                return False
            
            # 尝试分配TURN
            if self.use_tls:
                allocation_result, is_short_term = allocate_tcp_udp_with_fallback(
                    server_address, self.username, self.password,
                    self.realm, self.turn_server, self.use_tls
                )
            else:
                allocation_result, is_short_term = allocate_with_fallback(
                    server_address, self.username, self.password,
                    self.realm, self.turn_server, False
                )
            
            if not allocation_result:
                return False
            
            sock, nonce, realm, integrity_key, actual_server, *extra = allocation_result
            mi_algorithm = extra[0] if len(extra) > 0 else None
            
            try:
                # 尝试创建权限
                if not create_permission(
                    sock, nonce, realm, integrity_key,
                    target_ip, target_port, actual_server, self.username, mi_algorithm
                ):
                    # 权限创建失败，说明权限被拒绝
                    return True
                return False
            finally:
                sock.close()
        except Exception as e:
            # 如果出现异常，无法确定是否是权限问题
            return False
    
    def _test_protocol(self, server_ip: str, target_ip: str, target_port: int, protocol_name: str) -> Dict:
        """测试特定协议的数据包发送和响应检测"""
        protocol_result = {
            'protocol': protocol_name,
            'timestamp': datetime.now().isoformat(),
            'has_response': False,
            'response_data': None,
            'error': None
        }
        
        try:
            # 获取协议数据包
            packet_data = get_protocol_packet(protocol_name)
            if not packet_data:
                protocol_result['error'] = f'Protocol {protocol_name} not found'
                return protocol_result
            
            # 建立TURN连接
            server_address = resolve_server_address(self.turn_server, self.turn_port)
            if not server_address:
                protocol_result['error'] = 'Failed to resolve TURN server'
                return protocol_result
            
            # 分配TURN（根据use_tls选择UDP或TCP+UDP）
            if self.use_tls:
                allocation_result, is_short_term = allocate_tcp_udp_with_fallback(
                    server_address, self.username, self.password,
                    self.realm, self.turn_server, self.use_tls
                )
                use_tcp_udp = True
            else:
                allocation_result, is_short_term = allocate_with_fallback(
                    server_address, self.username, self.password,
                    self.realm, self.turn_server, False
                )
                use_tcp_udp = False
            
            if not allocation_result:
                protocol_result['error'] = 'Allocation failed'
                return protocol_result
            
            sock, nonce, realm, integrity_key, actual_server, *extra = allocation_result
            mi_algorithm = extra[0] if len(extra) > 0 else None
            
            try:
                # 创建权限
                if not create_permission(
                    sock, nonce, realm, integrity_key,
                    target_ip, target_port, actual_server, self.username, mi_algorithm
                ):
                    protocol_result['error'] = 'Permission denied'
                    # 标记为权限被拒绝，这样上层可以跳过整个IP
                    protocol_result['permission_denied'] = True
                    return protocol_result
                
                # 绑定channel
                channel_number = 0x4000
                if not channel_bind(
                    sock, nonce, realm, integrity_key,
                    target_ip, target_port, channel_number, actual_server, self.username, mi_algorithm
                ):
                    protocol_result['error'] = 'Channel bind failed'
                    return protocol_result
                
                # 发送协议数据包
                print(f"      [*] 发送 {protocol_name} 数据包 ({len(packet_data)} bytes)...")
                if use_tcp_udp:
                    if not channel_data_tcp(sock, channel_number, packet_data, actual_server):
                        protocol_result['error'] = 'Failed to send data (TCP+UDP mode)'
                        return protocol_result
                else:
                    if not channel_data(sock, channel_number, packet_data, actual_server):
                        protocol_result['error'] = 'Failed to send data'
                        return protocol_result
                
                # 等待响应（检查是否有数据返回，而不是ICMP错误）
                sock.settimeout(3)
                try:
                    if use_tcp_udp:
                        data = sock.recv(2048)
                        addr = None
                    else:
                        data, addr = sock.recvfrom(2048)
                    
                    if data:
                        # 解析响应
                        try:
                            msg_type, tid, attrs = parse_attrs(data)
                            
                            # 检查是否是 Data indication（表示有数据返回）
                            if msg_type == STUN_DATA_INDICATION:
                                # 检查是否有ICMP属性（表示端口关闭）
                                icmp_attr = attrs.get(STUN_ATTR_ICMP)
                                if icmp_attr:
                                    # 有ICMP错误，端口可能关闭
                                    protocol_result['has_response'] = False
                                    protocol_result['response_data'] = 'ICMP error received (port may be closed)'
                                else:
                                    # 有数据返回，但不是ICMP错误，说明端口可能开放且有响应
                                    protocol_result['has_response'] = True
                                    # 尝试提取实际数据（如果有XOR-PEER-ADDRESS属性，说明是正常数据）
                                    xor_peer_attr = attrs.get(STUN_ATTR_XOR_PEER_ADDRESS)
                                    if xor_peer_attr:
                                        # 解析XOR-PEER-ADDRESS
                                        if len(xor_peer_attr) >= 8:
                                            family = xor_peer_attr[1]
                                            if family == 1:  # IPv4
                                                xor_port = struct.unpack("!H", xor_peer_attr[2:4])[0]
                                                xor_ip = xor_peer_attr[4:8]
                                                peer_ip = socket.inet_ntoa(bytes([xor_ip[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)]))
                                                peer_port = xor_port ^ (STUN_MAGIC_COOKIE >> 16)
                                                protocol_result['response_data'] = f'Received data from {peer_ip}:{peer_port}'
                                            else:
                                                protocol_result['response_data'] = f'Received data indication from {target_ip}:{target_port}'
                                        else:
                                            protocol_result['response_data'] = f'Received data indication from {target_ip}:{target_port}'
                                    else:
                                        protocol_result['response_data'] = f'Received data indication (no peer address)'
                            else:
                                # 其他类型的响应
                                protocol_result['has_response'] = True
                                protocol_result['response_data'] = f'Received message type: 0x{msg_type:04x}'
                        except Exception as parse_error:
                            # 解析失败，但收到了数据，可能是有响应
                            protocol_result['has_response'] = True
                            protocol_result['response_data'] = f'Received {len(data)} bytes (parse error: {parse_error})'
                
                except socket.timeout:
                    # 超时，可能没有响应或端口被过滤
                    protocol_result['has_response'] = False
                    protocol_result['response_data'] = 'Timeout (no response)'
                except Exception as e:
                    protocol_result['error'] = f'Error receiving response: {e}'
            
            finally:
                sock.close()
        
        except Exception as e:
            protocol_result['error'] = str(e)
            import traceback
            traceback.print_exc()
        
        return protocol_result
    
    def run_test(self, num_threads: int = 4):
        """运行完整测试"""
        print("="*70)
        print("🚀 开始UDP TURN服务器综合测试")
        print("="*70)
        print(f"TURN服务器: {self.turn_server}:{self.turn_port}")
        print(f"用户名: {self.username}")
        print(f"测试IP数量: {len(self.test_ips)}")
        print(f"测试端口数量: {len(self.test_ports)}")
        print(f"输出文件: {self.output_file}")
        print()
        
        # 步骤1: 发现服务器IP
        print("[步骤1] 发现TURN服务器IP...")
        server_ips = self.discover_server_ips()
        if not server_ips:
            print("[-] 无法发现TURN服务器IP，退出")
            return
        
        # 步骤2: 测试服务器能力
        print("\n[步骤2] 测试TURN服务器能力...")
        udp_enabled_ips = []
        for server_ip in server_ips:
            cap = self.test_capabilities(server_ip)
            
            # 只保存有UDP或TCP+UDP能力的服务器IP
            if cap.get('udp', False) or cap.get('tcp_udp', False):
                udp_enabled_ips.append(server_ip)
        
        self._save_results()
        
        # 检查是否有UDP能力
        if not udp_enabled_ips:
            print("[-] TURN服务器不支持UDP或TCP+UDP转发，跳过内网测试")
            return
        
        # 步骤3: 测试内网IP转发（多线程）
        print("\n[步骤3] 测试内网IP转发能力...")
        print(f"使用 {num_threads} 个线程")
        
        # 创建任务队列
        task_queue = queue.Queue()
        for target_ip in self.test_ips:
            task_queue.put(target_ip)
        
        # 工作线程
        def worker():
            while True:
                try:
                    target_ip = task_queue.get(timeout=1)
                    print(f"\n[线程] 测试目标: {target_ip}")
                    
                    # 使用第一个有UDP能力的IP
                    server_ip = udp_enabled_ips[0] if udp_enabled_ips else server_ips[0]
                    
                    self.test_internal_network_access(server_ip, target_ip)
                    
                    task_queue.task_done()
                except queue.Empty:
                    break
                except Exception as e:
                    print(f"[-] 线程错误: {e}")
                    task_queue.task_done()
        
        # 启动线程
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        # 等待所有任务完成
        task_queue.join()
        
        # 等待所有线程完成
        for t in threads:
            t.join()
        
        print("\n" + "="*70)
        print("📊 测试完成")
        print("="*70)
        self._print_summary()
        self._save_results()
    
    def _print_summary(self):
        """打印测试摘要"""
        print(f"\n测试结果已保存到: {self.output_file}")
        print(f"\n能力测试结果:")
        
        if self.turn_server in self.results:
            for ip, data in self.results[self.turn_server].items():
                caps = data.get('capabilities', {})
                print(f"  {ip}:")
                print(f"    UDP: {caps.get('udp', False)}")
                print(f"    TCP+UDP: {caps.get('tcp_udp', False)}")
        
        print(f"\n内网测试结果:")
        if self.turn_server in self.results:
            for ip, data in self.results[self.turn_server].items():
                tested_targets = data.get('tested_targets', {})
                for target_ip, target_data in tested_targets.items():
                    if target_data.get('permission_denied'):
                        print(f"  [{ip}] {target_ip}: 权限被拒绝")
                    else:
                        ports_tested = len(target_data.get('ports', {}))
                        ports_open = sum(1 for r in target_data.get('ports', {}).values() 
                                        if r.get('port_status') in ['open|filtered', 'open', 'filtered'])
                        protocols_found = sum(1 for r in target_data.get('ports', {}).values()
                                            for p in r.get('protocols_tested', {}).values()
                                            if p.get('has_response', False))
                        print(f"  [{ip}] {target_ip}: {ports_open}/{ports_tested} 端口开放，{protocols_found} 个协议有响应")


def main():
    parser = argparse.ArgumentParser(description='TURN服务器UDP转发综合测试脚本')
    parser.add_argument('--turn-server', required=True, help='TURN服务器域名')
    parser.add_argument('--turn-port', type=int, default=3478, help='TURN服务器端口')
    parser.add_argument('--username', required=True, help='TURN用户名')
    parser.add_argument('--password', required=True, help='TURN密码')
    parser.add_argument('--realm', help='TURN认证域')
    parser.add_argument('--tls', action='store_true', help='使用TLS')
    parser.add_argument('--output', default='turn_udp_test_results.json', help='输出文件')
    parser.add_argument('--threads', type=int, default=4, help='线程数')
    parser.add_argument('--ip-file', help='自定义测试IP列表文件')
    parser.add_argument('--port-file', help='自定义测试端口列表文件')
    
    args = parser.parse_args()
    
    tester = ComprehensiveUDPTURNTester(
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tls=args.tls,
        output_file=args.output,
        ip_file=args.ip_file,
        port_file=args.port_file
    )
    
    try:
        tester.run_test(num_threads=args.threads)
    except KeyboardInterrupt:
        print("\n[+] 测试被用户中断")
        tester._save_results()
        print(f"[+] 结果已保存到: {args.output}")


if __name__ == "__main__":
    main()

