#!/usr/bin/env python3
"""
无认证TURN服务器测试脚本
参考RFC 8656 Section 7.2：服务器可以允许无认证的Allocate请求
支持UDP、TCP+UDP、TCP三种模式，以及内网IP转发测试（单个或批量）
"""

import argparse
import json
import os
import sys
import socket
import struct
import threading
import time
import queue
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import ssl

# 导入TURN相关模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'turn_utils'))
from turn_client import (
    STUN_ALLOCATE_REQUEST, STUN_ALLOCATE_SUCCESS_RESPONSE, STUN_ALLOCATE_ERROR_RESPONSE,
    STUN_CREATE_PERMISSION_REQUEST, STUN_CREATE_PERMISSION_SUCCESS_RESPONSE, STUN_CREATE_PERMISSION_ERROR_RESPONSE,
    STUN_CONNECT_REQUEST, STUN_CONNECTION_BIND_REQUEST,
    STUN_ATTR_REQUESTED_TRANSPORT, STUN_ATTR_XOR_PEER_ADDRESS,
    STUN_ATTR_ERROR_CODE, STUN_ATTR_CONNECTION_ID, STUN_ATTR_REALM, STUN_ATTR_NONCE,
    STUN_MAGIC_COOKIE, gen_tid, build_msg, parse_attrs, stun_attr, resolve_peer_address
)

# XOR-RELAYED-ADDRESS属性类型（RFC 8656 Section 18.5）
STUN_ATTR_XOR_RELAYED_ADDRESS = 0x0016
from turn_server_discovery import TURNServerDiscovery


class NoAuthTURNTester:
    """无认证TURN服务器测试器"""
    
    def __init__(self, turn_server: str, turn_port: int, use_tls: bool = False,
                 output_file: str = "no_auth_turn_test_results.json",
                 ip_file: Optional[str] = None, port_file: Optional[str] = None,
                 sni_hostname: Optional[str] = None, send_sni: bool = True):
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.use_tls = use_tls
        self.output_file = output_file
        self.ip_file = ip_file
        self.port_file = port_file
        self.sni_hostname = sni_hostname
        self.send_sni = send_sni
        
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
            ip_file = self.ip_file or 'ip_files/standard_test_ips.txt'
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
            port_file = self.port_file or 'port_files/standard_test_ports.txt'
            with open(port_file, 'r', encoding="utf-8") as f:
                ports = []
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '#' in line:
                        line = line.split('#')[0].strip()
                    if line:
                        try:
                            ports.append(int(line))
                        except ValueError:
                            continue
                print(f"[+] 使用测试端口文件: {port_file}（共 {len(ports)} 条）")
                return ports
        except FileNotFoundError:
            if self.port_file:
                print(f"[-] 指定的端口文件 {self.port_file} 未找到，使用默认端口列表")
            else:
                print("[-] standard_test_ports.txt not found, using default ports")
            return [80, 443]
    
    def _load_or_init_results(self) -> Dict:
        """加载已有结果或初始化新结果"""
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    results = json.load(f)
                    print(f"[+] 加载已有结果: {self.output_file}")
                    return results
            except Exception as e:
                print(f"[-] 加载结果文件失败: {e}，使用新结果")
        
        return {
            self.turn_server: {}
        }
    
    def _save_results(self):
        """保存结果到文件"""
        with self.lock:
            try:
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"[-] 保存结果失败: {e}")
    
    def _allocate_udp_no_auth(self, server_address: Tuple[str, int]) -> Optional[Tuple]:
        """无认证UDP TURN分配
        
        Returns:
            (sock, relayed_address, relayed_port, attrs) 或 None
        """
        print(f"[+] 尝试无认证UDP TURN分配: {server_address}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        try:
            # 发送无认证的Allocate请求（不包含MESSAGE-INTEGRITY）
            tid = gen_tid()
            attrs = [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))  # UDP=17
            ]
            req = build_msg(STUN_ALLOCATE_REQUEST, tid, attrs, integrity_key=None, add_fingerprint=True)
            sock.sendto(req, server_address)
            
            data, _ = sock.recvfrom(2000)
            msg_type, tid, resp_attrs = parse_attrs(data)
            
            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                print("[+] 无认证UDP TURN分配成功")
                
                # 提取中继地址
                relayed_addr = resp_attrs.get(STUN_ATTR_XOR_RELAYED_ADDRESS)
                if relayed_addr:
                    # XOR解码
                    family = relayed_addr[0]
                    port_xor = struct.unpack("!H", relayed_addr[2:4])[0]
                    port = port_xor ^ (STUN_MAGIC_COOKIE >> 16)
                    ip_bytes = relayed_addr[4:8]
                    ip_xor = struct.unpack("!I", ip_bytes)[0]
                    ip_int = ip_xor ^ STUN_MAGIC_COOKIE
                    relayed_ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                    print(f"[+] 中继地址: {relayed_ip}:{port}")
                    return (sock, relayed_ip, port, resp_attrs)
                else:
                    print("[-] 响应中未找到XOR-RELAYED-ADDRESS")
                    sock.close()
                    return None
            elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = resp_attrs.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    error_reason = error_code[4:].decode('utf-8', errors='ignore')
                    print(f"[-] 分配失败: {error_class}{error_number:02d} {error_reason}")
                sock.close()
                return None
            else:
                print(f"[-] 意外的响应类型: 0x{msg_type:04x}")
                sock.close()
                return None
                
        except socket.timeout:
            print("[-] 等待响应超时")
            sock.close()
            return None
        except Exception as e:
            print(f"[-] UDP分配失败: {e}")
            sock.close()
            return None
    
    def _allocate_tcp_no_auth(self, server_address: Tuple[str, int]) -> Optional[Tuple]:
        """无认证TCP TURN分配
        
        Returns:
            (control_sock, relayed_address, relayed_port, attrs) 或 None
        """
        print(f"[+] 尝试无认证TCP TURN分配: {server_address}")
        
        control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        control_sock.settimeout(10)
        
        try:
            # 连接到TURN服务器
            control_sock.connect(server_address)
            print(f"[+] 已连接到TURN服务器 {server_address}")
            
            # 如果使用TLS，建立SSL连接
            if self.use_tls:
                print("[+] 建立TLS连接...")
                context = ssl.create_default_context()
                
                if not self.send_sni:
                    ssl_hostname = None
                    print("[+] SNI已禁用：TLS握手时不发送SNI")
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                elif self.sni_hostname:
                    ssl_hostname = self.sni_hostname
                    print(f"[+] 使用自定义SNI主机名: {ssl_hostname}")
                else:
                    ssl_hostname = server_address[0]
                
                # 证书验证逻辑
                if self.send_sni:
                    if self.sni_hostname:
                        try:
                            socket.inet_aton(ssl_hostname)
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            print("[!] SNI主机名是IP地址，禁用SSL证书验证")
                        except socket.error:
                            print(f"[+] 使用自定义SNI '{self.sni_hostname}'，启用证书验证")
                    else:
                        try:
                            socket.inet_aton(ssl_hostname)
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            print("[!] SNI主机名是IP地址，禁用SSL证书验证")
                        except socket.error:
                            print(f"[+] 使用SNI '{ssl_hostname}'，启用证书验证")
                
                control_sock = context.wrap_socket(control_sock, server_hostname=ssl_hostname)
                print("[+] TLS连接已建立")
            
            # 发送无认证的Allocate请求
            tid = gen_tid()
            attrs = [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00"))  # TCP=6
            ]
            req = build_msg(STUN_ALLOCATE_REQUEST, tid, attrs, integrity_key=None, add_fingerprint=True)
            control_sock.send(req)
            
            data = control_sock.recv(2000)
            msg_type, tid, resp_attrs = parse_attrs(data)
            
            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                print("[+] 无认证TCP TURN分配成功")
                
                # 提取中继地址
                relayed_addr = resp_attrs.get(STUN_ATTR_XOR_RELAYED_ADDRESS)
                if relayed_addr:
                    family = relayed_addr[0]
                    port_xor = struct.unpack("!H", relayed_addr[2:4])[0]
                    port = port_xor ^ (STUN_MAGIC_COOKIE >> 16)
                    ip_bytes = relayed_addr[4:8]
                    ip_xor = struct.unpack("!I", ip_bytes)[0]
                    ip_int = ip_xor ^ STUN_MAGIC_COOKIE
                    relayed_ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                    print(f"[+] 中继地址: {relayed_ip}:{port}")
                    return (control_sock, relayed_ip, port, resp_attrs)
                else:
                    print("[-] 响应中未找到XOR-RELAYED-ADDRESS")
                    control_sock.close()
                    return None
            elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = resp_attrs.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    error_reason = error_code[4:].decode('utf-8', errors='ignore')
                    print(f"[-] 分配失败: {error_class}{error_number:02d} {error_reason}")
                control_sock.close()
                return None
            else:
                print(f"[-] 意外的响应类型: 0x{msg_type:04x}")
                control_sock.close()
                return None
                
        except socket.timeout:
            print("[-] 等待响应超时")
            control_sock.close()
            return None
        except Exception as e:
            print(f"[-] TCP分配失败: {e}")
            control_sock.close()
            return None
    
    def _create_permission_no_auth(self, sock, peer_ip: str, peer_port: int, 
                                     server_address: Optional[Tuple[str, int]] = None) -> bool:
        """无认证创建权限"""
        if server_address is None:
            server_address = (self.turn_server, self.turn_port)
        
        print(f"[+] 创建权限: {peer_ip}:{peer_port}")
        
        resolved_peer_ip = resolve_peer_address(peer_ip)
        if not resolved_peer_ip:
            print(f"[-] 无法解析对等方地址 {peer_ip}")
            return False
        
        peer_addr = socket.inet_aton(resolved_peer_ip)
        xor_port = peer_port ^ (STUN_MAGIC_COOKIE >> 16)
        xor_ip = bytes([peer_addr[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)])
        xor_addr = struct.pack("!BBH", 0, 1, xor_port) + xor_ip
        
        tid = gen_tid()
        attrs = [
            stun_attr(STUN_ATTR_XOR_PEER_ADDRESS, xor_addr)
        ]
        req = build_msg(STUN_CREATE_PERMISSION_REQUEST, tid, attrs, integrity_key=None, add_fingerprint=True)
        
        # 检查是否为SSL套接字
        if hasattr(sock, '_sslobj') or sock.__class__.__name__ == 'SSLSocket':
            sock.send(req)
            data = sock.recv(2000)
        else:
            sock.sendto(req, server_address)
            data, _ = sock.recvfrom(2000)
        
        msg_type, tid, attrs = parse_attrs(data)
        
        if msg_type == STUN_CREATE_PERMISSION_SUCCESS_RESPONSE:
            print("[+] 权限创建成功")
            return True
        elif msg_type == STUN_CREATE_PERMISSION_ERROR_RESPONSE:
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                error_reason = error_code[4:].decode('utf-8', errors='ignore')
                print(f"[-] 权限创建失败: {error_class}{error_number:02d} {error_reason}")
            return False
        else:
            print(f"[-] 意外的响应类型: 0x{msg_type:04x}")
            return False
    
    def _tcp_connect_no_auth(self, control_sock, peer_ip: str, peer_port: int) -> Tuple[Optional[int], Optional[str]]:
        """无认证TCP Connect请求
        
        Returns:
            (connection_id, error_info): 如果成功返回(connection_id, None)，失败返回(None, error_info)
        """
        print(f"[+] 发起TCP连接到 {peer_ip}:{peer_port}")
        
        resolved_peer_ip = resolve_peer_address(peer_ip)
        if not resolved_peer_ip:
            error_msg = f"无法解析对等方地址 {peer_ip}"
            print(f"[-] {error_msg}")
            return (None, error_msg)
        
        peer_addr = socket.inet_aton(resolved_peer_ip)
        xor_port = peer_port ^ (STUN_MAGIC_COOKIE >> 16)
        xor_ip = bytes([peer_addr[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)])
        xor_addr = struct.pack("!BBH", 0, 1, xor_port) + xor_ip
        
        tid = gen_tid()
        attrs = [
            stun_attr(STUN_ATTR_XOR_PEER_ADDRESS, xor_addr)
        ]
        req = build_msg(STUN_CONNECT_REQUEST, tid, attrs, integrity_key=None, add_fingerprint=True)
        control_sock.send(req)
        
        # 等待Connect响应（10秒超时）
        original_timeout = control_sock.gettimeout()
        control_sock.settimeout(10)
        try:
            data = control_sock.recv(2000)
        except socket.timeout:
            error_msg = "等待Connect响应超时（10秒）"
            print(f"[-] {error_msg}")
            control_sock.settimeout(original_timeout)
            return (None, error_msg)
        except Exception as e:
            error_msg = f"接收Connect响应错误: {e}"
            print(f"[-] {error_msg}")
            control_sock.settimeout(original_timeout)
            return (None, error_msg)
        finally:
            control_sock.settimeout(original_timeout)
        
        if not data:
            error_msg = "Connect响应中无数据"
            print(f"[-] {error_msg}")
            return (None, error_msg)
        
        msg_type, tid, attrs = parse_attrs(data)
        
        if msg_type == 0x010a:  # Connect Success Response
            print("[+] Connect成功")
            connection_id = attrs.get(STUN_ATTR_CONNECTION_ID)
            if connection_id:
                conn_id = struct.unpack("!I", connection_id)[0]
                print(f"[+] 连接ID: {conn_id}")
                return (conn_id, None)
            error_msg = "Connect成功但响应中无连接ID"
            print(f"[-] {error_msg}")
            return (None, error_msg)
        elif msg_type == 0x011a:  # Connect Error Response
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                error_reason = error_code[4:].decode('utf-8', errors='ignore')
                error_msg = f"{error_class}{error_number:02d} {error_reason}"
                print(f"[-] Connect失败: {error_msg}")
                return (None, error_msg)
            error_msg = "Connect错误响应但无错误代码"
            print(f"[-] {error_msg}")
            return (None, error_msg)
        else:
            error_msg = f"意外的响应类型: 0x{msg_type:04x}"
            print(f"[-] {error_msg}")
            return (None, error_msg)
    
    def test_capabilities(self, server_ip: str) -> Dict[str, bool]:
        """测试TURN服务器能力"""
        print(f"\n[+] 测试服务器能力: {server_ip}")
        
        server_address = (server_ip, self.turn_port)
        capabilities = {'udp': False, 'tcp': False}
        
        # 测试UDP
        print("  [1/2] 测试UDP TURN...")
        try:
            result = self._allocate_udp_no_auth(server_address)
            if result:
                capabilities['udp'] = True
                sock, _, _, _ = result
                sock.close()
        except Exception as e:
            print(f"  [-] UDP测试失败: {e}")
        
        # 测试TCP
        print("  [2/2] 测试TCP TURN...")
        try:
            result = self._allocate_tcp_no_auth(server_address)
            if result:
                capabilities['tcp'] = True
                control_sock, _, _, _ = result
                control_sock.close()
        except Exception as e:
            print(f"  [-] TCP测试失败: {e}")
        
        # 保存能力测试结果
        if self.turn_server not in self.results:
            self.results[self.turn_server] = {}
        if server_ip not in self.results[self.turn_server]:
            self.results[self.turn_server][server_ip] = {
                'metadata': {'turn_port': self.turn_port, 'no_auth': True},
                'capabilities': {},
                'tested_targets': {}
            }
        self.results[self.turn_server][server_ip]['capabilities'] = capabilities
        self._save_results()
        
        return capabilities
    
    def test_internal_network_access(self, server_ip: str, target_ip: str):
        """测试内网IP转发能力"""
        print(f"\n[+] 测试内网IP转发: {target_ip}")
        
        server_address = (server_ip, self.turn_port)
        
        # 初始化结构
        if self.turn_server not in self.results:
            self.results[self.turn_server] = {}
        if server_ip not in self.results[self.turn_server]:
            self.results[self.turn_server][server_ip] = {
                'metadata': {'turn_port': self.turn_port, 'no_auth': True},
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
        
        control_sock = None
        
        try:
            # 建立TCP TURN连接
            print(f"  [*] 建立TCP TURN连接...")
            result = self._allocate_tcp_no_auth(server_address)
            
            if not result:
                print(f"  [-] 无法建立TURN连接")
                self.results[self.turn_server][server_ip]['tested_targets'][target_ip]['error'] = 'Allocation failed'
                self._save_results()
                return
            
            control_sock, _, _, _ = result
            print(f"  [+] TURN连接已建立，将测试 {len(self.test_ports)} 个端口")
            
            # 测试所有端口
            for i, port in enumerate(self.test_ports, 1):
                print(f"  [{i}/{len(self.test_ports)}] 测试端口{port}...")
                
                result = self._test_port(server_ip, target_ip, port, control_sock)
                self.results[self.turn_server][server_ip]['tested_targets'][target_ip]['ports'][str(port)] = result
                self._save_results()
                
                # 如果权限被拒绝，跳过后续端口
                if result.get('permission_denied', False):
                    print(f"  [-] IP {target_ip} 权限被拒绝，跳过后续端口")
                    self.results[self.turn_server][server_ip]['tested_targets'][target_ip]['permission_denied'] = True
                    break
        
        finally:
            if control_sock:
                control_sock.close()
                print(f"  [*] TURN连接已关闭")
    
    def _test_port(self, server_ip: str, target_ip: str, target_port: int, 
                   control_sock) -> Dict:
        """测试特定端口的TCP转发能力"""
        result = {
            'port': target_port,
            'timestamp': datetime.now().isoformat(),
            'permission_denied': False,
            'connection_success': False,
            'error': None
        }
        
        try:
            # 创建权限
            if not self._create_permission_no_auth(control_sock, target_ip, target_port):
                result['permission_denied'] = True
                result['error'] = 'Permission denied'
                return result
            
            # 发起Connect请求
            connection_id, error_info = self._tcp_connect_no_auth(control_sock, target_ip, target_port)
            if connection_id:
                result['connection_success'] = True
                result['connection_id'] = connection_id
            else:
                # 使用详细的错误信息
                result['error'] = error_info if error_info else 'Connect failed'
        
        except Exception as e:
            result['error'] = f"异常: {str(e)}"
        
        return result
    
    def run_single_test(self, target_ip: str):
        """运行单个IP的测试"""
        print("\n" + "="*70)
        print("🔍 无认证TURN服务器测试（单个IP）")
        print("="*70)
        
        # 发现服务器IP
        server_ips_set = self.discovery.discover_all_ips(self.turn_server)
        server_ips = list(server_ips_set)
        if not server_ips:
            print(f"[-] 无法解析TURN服务器: {self.turn_server}")
            return
        
        print(f"[+] 发现 {len(server_ips)} 个服务器IP")
        
        # 测试能力
        print("\n[步骤1] 测试TURN服务器能力...")
        tcp_enabled_ips = []
        for server_ip in server_ips:
            cap = self.test_capabilities(server_ip)
            if cap.get('tcp', False):
                tcp_enabled_ips.append(server_ip)
        
        if not tcp_enabled_ips:
            print("[-] TURN服务器不支持TCP转发，跳过内网测试")
            return
        
        # 测试内网IP转发
        print(f"\n[步骤2] 测试内网IP转发: {target_ip}")
        server_ip = tcp_enabled_ips[0]
        self.test_internal_network_access(server_ip, target_ip)
        
        print("\n" + "="*70)
        print("📊 测试完成")
        print("="*70)
        self._save_results()
    
    def run_batch_test(self, num_threads: int = 4):
        """运行批量测试"""
        print("\n" + "="*70)
        print("🔍 无认证TURN服务器测试（批量）")
        print("="*70)
        
        # 发现服务器IP
        server_ips_set = self.discovery.discover_all_ips(self.turn_server)
        server_ips = list(server_ips_set)
        if not server_ips:
            print(f"[-] 无法解析TURN服务器: {self.turn_server}")
            return
        
        print(f"[+] 发现 {len(server_ips)} 个服务器IP")
        
        # 测试能力
        print("\n[步骤1] 测试TURN服务器能力...")
        tcp_enabled_ips = []
        for server_ip in server_ips:
            cap = self.test_capabilities(server_ip)
            if cap.get('tcp', False):
                tcp_enabled_ips.append(server_ip)
        
        if not tcp_enabled_ips:
            print("[-] TURN服务器不支持TCP转发，跳过内网测试")
            return
        
        # 批量测试内网IP转发
        print(f"\n[步骤2] 批量测试内网IP转发（{num_threads} 线程）...")
        
        task_queue = queue.Queue()
        for target_ip in self.test_ips:
            task_queue.put(target_ip)
        
        def worker():
            while True:
                try:
                    target_ip = task_queue.get(timeout=1)
                    print(f"\n[线程] 测试目标: {target_ip}")
                    server_ip = tcp_enabled_ips[0]
                    self.test_internal_network_access(server_ip, target_ip)
                    task_queue.task_done()
                except queue.Empty:
                    break
                except Exception as e:
                    print(f"[-] 线程错误: {e}")
                    task_queue.task_done()
        
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        task_queue.join()
        for t in threads:
            t.join()
        
        print("\n" + "="*70)
        print("📊 测试完成")
        print("="*70)
        self._save_results()


def main():
    parser = argparse.ArgumentParser(description='无认证TURN服务器测试脚本')
    parser.add_argument('--turn-server', required=True, help='TURN服务器域名或IP')
    parser.add_argument('--turn-port', type=int, default=3478, help='TURN服务器端口')
    parser.add_argument('--tls', action='store_true', help='使用TLS')
    parser.add_argument('--sni', help='自定义SNI主机名')
    parser.add_argument('--no-sni', action='store_true', help='不发送SNI')
    parser.add_argument('--output', default='no_auth_turn_test_results.json', help='输出文件')
    parser.add_argument('--ip-file', help='测试IP文件')
    parser.add_argument('--port-file', help='测试端口文件')
    parser.add_argument('--single-ip', help='测试单个IP（不进行批量测试）')
    parser.add_argument('--threads', type=int, default=4, help='批量测试线程数')
    
    args = parser.parse_args()
    
    tester = NoAuthTURNTester(
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        use_tls=args.tls,
        output_file=args.output,
        ip_file=args.ip_file,
        port_file=args.port_file,
        sni_hostname=args.sni,
        send_sni=not args.no_sni
    )
    
    if args.single_ip:
        tester.run_single_test(args.single_ip)
    else:
        tester.run_batch_test(args.threads)


if __name__ == '__main__':
    main()

