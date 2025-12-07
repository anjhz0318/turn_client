#!/usr/bin/env python3
"""
综合性TURN服务器测试脚本
支持多线程、断点续测、能力测试和内网IP转发测试
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

# 导入TURN相关模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'turn_utils'))
from turn_server_discovery import TURNServerDiscovery
from test_turn_capabilities import test_udp_turn, test_tcp_udp_turn, test_tcp_turn, allocate_tcp_with_fallback
from turn_client import allocate_tcp, tcp_connect, create_permission

class ComprehensiveTURNTester:
    """综合性TURN服务器测试器"""
    
    def __init__(self, turn_server: str, turn_port: int, username: str, 
                 password: str, realm: str = None, use_tls: bool = False,
                 output_file: str = "turn_test_results.json", reuse_connection: bool = True,
                 use_short_term_credential: bool = False, ip_file: Optional[str] = None,
                 port_file: Optional[str] = None, sni_hostname: Optional[str] = None):
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.username = username
        self.password = password
        self.realm = realm or "default"
        self.use_tls = use_tls
        self.output_file = output_file
        self.reuse_connection = reuse_connection
        self.use_short_term_credential = use_short_term_credential
        self.ip_file = ip_file
        self.port_file = port_file
        self.sni_hostname = sni_hostname
        
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
                ports = []
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # 处理行内注释：去掉 # 及其后面的内容
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
        """保存结果到文件"""
        try:
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
        """测试TURN服务器能力"""
        print(f"\n[+] 测试服务器能力: {server_ip}")
        
        server_address = (server_ip, self.turn_port)
        capabilities = {}
        
        # 测试UDP（使用回退机制：先尝试长期凭据，如果400错误则回退为短期凭据）
        print("  [1/3] 测试UDP TURN...")
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
        
        # 测试TCP+UDP（使用回退机制：先尝试长期凭据，如果400错误则回退为短期凭据）
        print("  [2/3] 测试TCP+UDP TURN...")
        try:
            test_ip = "8.8.8.8"
            test_port = 53
            result = test_tcp_udp_turn(
                server_address, self.username, self.password, 
                self.realm, self.turn_server, self.use_tls, test_ip, test_port, False,
                sni_hostname=self.sni_hostname  # 只有明确指定 --sni 时才传递
            )
            capabilities['tcp_udp'] = result
        except Exception as e:
            print(f"  [-] TCP+UDP测试失败: {e}")
            capabilities['tcp_udp'] = False
        
        # 测试TCP（使用回退机制：先尝试长期凭据，如果400错误则回退为短期凭据）
        print("  [3/3] 测试TCP TURN...")
        try:
            test_ip = "httpbin.org"
            test_port = 80
            result = test_tcp_turn(
                server_address, self.username, self.password, 
                self.realm, self.turn_server, self.use_tls, test_ip, test_port, False,
                sni_hostname=self.sni_hostname  # 只有明确指定 --sni 时才传递
            )
            capabilities['tcp'] = result
        except Exception as e:
            print(f"  [-] TCP测试失败: {e}")
            capabilities['tcp'] = False
        
        # 保存能力测试结果
        if self.turn_server in self.results and server_ip in self.results[self.turn_server]:
            self.results[self.turn_server][server_ip]['capabilities'] = capabilities
            self._save_results()
        
        return capabilities
    
    def test_internal_network_access(self, server_ip: str, target_ip: str, reuse_connection: bool = True):
        """测试内网IP转发能力
        
        Args:
            reuse_connection: 是否复用同一个控制连接测试该IP的所有端口
        """
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
        
        control_sock = None
        
        try:
            # 如果复用连接，先建立TURN连接（使用回退机制）
            if reuse_connection:
                print(f"  [*] 建立TURN连接（复用模式）...")
                server_address = (server_ip, self.turn_port)
                allocation_result, is_short_term = allocate_tcp_with_fallback(
                    server_address, self.username, self.password, 
                    self.realm, self.use_tls,
                    sni_hostname=self.sni_hostname  # 只有明确指定 --sni 时才传递
                )
                
                if not allocation_result:
                    print(f"  [-] 无法建立TURN连接")
                    self.results[self.turn_server][server_ip]['tested_targets'][target_ip]['error'] = 'Allocation failed'
                    self._save_results()
                    return
                
                control_sock, nonce, realm, integrity_key, actual_server, *extra = allocation_result
                if len(extra) > 0:
                    mi_algorithm = extra[0]  # 可能存在 mi_algorithm
                if is_short_term:
                    print(f"  [+] 使用短期凭据建立TURN连接")
                print(f"  [+] TURN连接已建立，将测试 {len(self.test_ports)} 个端口")
            
            # 测试所有端口
            for i, port in enumerate(self.test_ports, 1):
                print(f"  [{i}/{len(self.test_ports)}] 测试端口{port}...")
                
                if reuse_connection and control_sock:
                    # 复用连接
                    result = self._test_port(server_ip, target_ip, port,
                                            control_sock, nonce, realm, integrity_key, actual_server)
                else:
                    # 为每个端口建立新连接
                    result = self._test_port(server_ip, target_ip, port)
                
                self.results[self.turn_server][server_ip]['tested_targets'][target_ip]['ports'][str(port)] = result
                self._save_results()
                
                # 如果权限被拒绝，跳过后续端口
                if result.get('permission_denied', False):
                    print(f"  [-] IP {target_ip} 权限被拒绝，跳过后续端口")
                    self.results[self.turn_server][server_ip]['tested_targets'][target_ip]['permission_denied'] = True
                    break
        
        finally:
            # 关闭复用连接
            if reuse_connection and control_sock:
                control_sock.close()
                print(f"  [*] TURN连接已关闭")
    
    def _test_port(self, server_ip: str, target_ip: str, target_port: int, 
                   control_sock=None, nonce=None, realm=None, integrity_key=None, actual_server=None) -> Dict:
        """测试特定端口的TCP转发能力
        
        Args:
            control_sock: 可选的复用控制连接
            nonce: 可选的nonce值（用于连接复用）
            realm: 可选的realm值（用于连接复用）
            integrity_key: 可选的完整性密钥（用于连接复用）
            actual_server: 可选的服务器地址（用于连接复用）
        """
        result = {
            'port': target_port,
            'timestamp': datetime.now().isoformat(),
            'permission_denied': False,
            'connection_success': False,
            'error': None
        }
        
        should_close_connection = False
        
        try:
            # 如果没有提供复用的连接，则创建新连接（使用回退机制）
            if control_sock is None:
                server_address = (server_ip, self.turn_port)
                
                # 分配TCP TURN（使用回退机制：先尝试长期凭据，如果400错误则回退为短期凭据）
                allocation_result, is_short_term = allocate_tcp_with_fallback(
                    server_address, self.username, self.password, 
                    self.realm, self.use_tls,
                    sni_hostname=self.sni_hostname  # 只有明确指定 --sni 时才传递
                )
                
                if not allocation_result:
                    result['error'] = 'Allocation failed'
                    return result
                
                control_sock, nonce, realm, integrity_key, actual_server, *extra = allocation_result
                if len(extra) > 0:
                    mi_algorithm = extra[0]  # 可能存在 mi_algorithm
                should_close_connection = True
            
            # 创建权限
            if not create_permission(
                control_sock, nonce, realm, integrity_key,
                target_ip, target_port, actual_server, self.username
            ):
                result['permission_denied'] = True
                if should_close_connection:
                    control_sock.close()
                return result
            
            # 尝试TCP连接
            connection_id = tcp_connect(
                control_sock, nonce, realm, integrity_key,
                target_ip, target_port, self.username
            )
            
            if connection_id:
                result['connection_success'] = True
                result['connection_id'] = hex(connection_id) if connection_id else None
            else:
                result['error'] = 'Connection failed'
            
            if should_close_connection:
                control_sock.close()
            
        except Exception as e:
            result['error'] = str(e)
            if should_close_connection and control_sock:
                control_sock.close()
        
        return result
    
    def run_test(self, num_threads: int = 4):
        """运行完整测试"""
        print("="*70)
        print("🚀 开始TURN服务器综合测试")
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
        tcp_enabled_ips = []
        for server_ip in server_ips:
            cap = self.test_capabilities(server_ip)
            
            # 只保存有TCP能力的服务器IP
            if cap.get('tcp', False):
                tcp_enabled_ips.append(server_ip)
        
        self._save_results()
        
        # 检查是否有TCP能力
        if not tcp_enabled_ips:
            print("[-] TURN服务器不支持TCP转发，跳过内网测试")
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
                    
                    # 使用第一个有TCP能力的IP
                    server_ip = tcp_enabled_ips[0] if tcp_enabled_ips else server_ips[0]
                    
                    self.test_internal_network_access(server_ip, target_ip, reuse_connection=self.reuse_connection)
                    
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
                print(f"    TCP: {caps.get('tcp', False)}")
        
        print(f"\n内网测试结果:")
        if self.turn_server in self.results:
            for ip, data in self.results[self.turn_server].items():
                tested_targets = data.get('tested_targets', {})
                for target_ip, target_data in tested_targets.items():
                    if target_data.get('permission_denied'):
                        print(f"  [{ip}] {target_ip}: 权限被拒绝")
                    else:
                        ports_tested = len(target_data.get('ports', {}))
                        ports_success = sum(1 for r in target_data.get('ports', {}).values() 
                                           if r.get('connection_success', False))
                        print(f"  [{ip}] {target_ip}: {ports_success}/{ports_tested} 端口成功")
        
def main():
    parser = argparse.ArgumentParser(description='TURN服务器TCP转发综合测试脚本')
    parser.add_argument('--turn-server', required=True, help='TURN服务器域名')
    parser.add_argument('--turn-port', type=int, default=3478, help='TURN服务器端口')
    parser.add_argument('--username', required=True, help='TURN用户名')
    parser.add_argument('--password', required=True, help='TURN密码')
    parser.add_argument('--realm', help='TURN认证域')
    parser.add_argument('--tls', action='store_true', help='使用TLS')
    parser.add_argument('--output', default='turn_test_results.json', help='输出文件')
    parser.add_argument('--threads', type=int, default=4, help='线程数')
    parser.add_argument('--reuse-connection', action='store_true', help='复用控制连接（为每个IP建立一次连接，测试所有端口）')
    parser.add_argument('--no-reuse-connection', action='store_true', help='为每个端口建立新连接')
    parser.add_argument('--short-term-credential', action='store_true', 
                       help='已弃用：现在自动使用回退机制（先尝试长期凭据，如果400错误则回退为短期凭据）')
    parser.add_argument('--ip-file', help='自定义测试IP列表文件')
    parser.add_argument('--port-file', help='自定义测试端口列表文件')
    parser.add_argument('--sni', help='自定义SNI主机名（用于TLS握手，如果未指定则使用TURN服务器域名）')
    
    args = parser.parse_args()
    
    # 确定连接复用模式
    reuse_connection = args.reuse_connection if not args.no_reuse_connection else False
    
    # 如果用户指定了 --short-term-credential，给出提示
    if args.short_term_credential:
        print("[!] 注意：--short-term-credential 参数已弃用")
        print("[!] 现在会自动使用回退机制：先尝试长期凭据，如果收到400错误则回退为短期凭据")
        print()
    
    tester = ComprehensiveTURNTester(
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tls=args.tls,
        output_file=args.output,
        reuse_connection=reuse_connection,
        use_short_term_credential=False,  # 不再使用此参数，总是使用回退机制
        ip_file=args.ip_file,
        port_file=args.port_file,
        sni_hostname=args.sni
    )
    
    try:
        tester.run_test(num_threads=args.threads)
    except KeyboardInterrupt:
        print("\n[+] 测试被用户中断")
        tester._save_results()
        print(f"[+] 结果已保存到: {args.output}")

if __name__ == "__main__":
    main()
