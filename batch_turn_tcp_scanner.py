#!/usr/bin/env python3
"""
TURN代理批量TCP扫描器
基于turn_as_proxy_tcp_scanner.py，支持批量扫描多个内网IP的多个TCP端口

使用方法:
python batch_turn_tcp_scanner.py --turn-server <TURN服务器> --turn-port <端口> --username <用户名> --password <密码> --targets <IP列表> --ports <端口范围> [--tls] [--workers <线程数>]

支持从文件读取:
python batch_turn_tcp_scanner.py --turn-server <TURN服务器> --username <用户名> --password <密码> --targets-file <IP文件> --ports-file <端口文件>

文件格式示例:
# targets.txt
192.168.1.1
192.168.1.2-192.168.1.10
192.168.2.0/24

# ports.txt
22,23,80,443
3389,5900
8080-8443
"""

import sys
import time
import socket
import struct
import argparse
import threading
import json
from typing import List, Tuple, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

# 添加turn_utils到路径
sys.path.insert(0, '/home/turn_utils')
from turn_client import allocate_tcp, create_permission, tcp_connect, discover_turn_server_ips

class BatchTurnTcpScanner:
    def __init__(self, turn_server: str, turn_port: int, username: str, password: str, 
                 realm: str = None, use_tls: bool = False):
        """初始化批量TURN TCP扫描器"""
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls
        
        # 扫描结果
        self.results = []
        self.lock = threading.Lock()
        
    def parse_targets_from_file(self, file_path: str) -> List[str]:
        """从文件中读取目标IP列表"""
        targets = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue  # 跳过空行和注释
                    
                    # 支持多种格式
                    if ',' in line:
                        # 逗号分隔的多个IP
                        for target in line.split(','):
                            target = target.strip()
                            if target:
                                targets.extend(self.parse_targets(target))
                    else:
                        # 单个IP或IP范围
                        targets.extend(self.parse_targets(line))
                        
        except FileNotFoundError:
            print(f"[-] 文件不存在: {file_path}")
        except Exception as e:
            print(f"[-] 读取文件失败 {file_path}: {e}")
        
        return targets
    
    def parse_ports_from_file(self, file_path: str) -> List[int]:
        """从文件中读取端口列表"""
        ports = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue  # 跳过空行和注释
                    
                    # 支持多种格式
                    if ',' in line:
                        # 逗号分隔的多个端口
                        for port_range in line.split(','):
                            port_range = port_range.strip()
                            if port_range:
                                ports.extend(self.parse_ports(port_range))
                    else:
                        # 单个端口或端口范围
                        ports.extend(self.parse_ports(line))
                        
        except FileNotFoundError:
            print(f"[-] 文件不存在: {file_path}")
        except Exception as e:
            print(f"[-] 读取文件失败 {file_path}: {e}")
        
        return sorted(list(set(ports)))  # 去重并排序
    
    def parse_targets(self, targets_str: str) -> List[str]:
        targets = []
        for target in targets_str.split(','):
            target = target.strip()
            if '-' in target and not target.count('-') > 1:
                # IP范围，如 192.168.1.1-192.168.1.10
                try:
                    start_ip, end_ip = target.split('-')
                    start_ip = ipaddress.IPv4Address(start_ip.strip())
                    end_ip = ipaddress.IPv4Address(end_ip.strip())
                    
                    current_ip = start_ip
                    while current_ip <= end_ip:
                        targets.append(str(current_ip))
                        current_ip += 1
                except Exception as e:
                    print(f"[-] 解析IP范围失败 {target}: {e}")
            elif '/' in target:
                # CIDR网络，如 192.168.1.0/24
                try:
                    network = ipaddress.IPv4Network(target, strict=False)
                    for ip in network.hosts():
                        targets.append(str(ip))
                except Exception as e:
                    print(f"[-] 解析CIDR网络失败 {target}: {e}")
            else:
                # 单个IP
                targets.append(target)
        
        return targets
    
    def parse_ports(self, ports_str: str) -> List[int]:
        """解析端口列表"""
        ports = []
        for port_range in ports_str.split(','):
            port_range = port_range.strip()
            if '-' in port_range:
                # 端口范围，如 80-443
                try:
                    start_port, end_port = map(int, port_range.split('-'))
                    ports.extend(range(start_port, end_port + 1))
                except Exception as e:
                    print(f"[-] 解析端口范围失败 {port_range}: {e}")
            else:
                # 单个端口
                try:
                    ports.append(int(port_range))
                except Exception as e:
                    print(f"[-] 解析端口失败 {port_range}: {e}")
        
        return sorted(list(set(ports)))  # 去重并排序
    
    def establish_turn_connection(self):
        """建立TURN连接并返回连接信息"""
        print(f"[+] 连接到TURN服务器 {self.turn_server}:{self.turn_port}")
        
        # 发现TURN服务器IP
        server_ips = discover_turn_server_ips(self.turn_server)
        if not server_ips:
            raise Exception(f"无法解析TURN服务器 {self.turn_server}")
        
        print(f"[+] 发现TURN服务器IP: {server_ips}")
        
        # 尝试连接TURN服务器
        for server_ip in server_ips:
            try:
                server_address = (server_ip, self.turn_port)
                print(f"[+] 尝试连接TURN服务器: {server_address}")
                
                result = allocate_tcp(server_address, self.username, self.password, 
                                    self.realm, self.use_tls, self.turn_server)
                if result:
                    control_sock, nonce, realm, integrity_key, actual_server_address = result
                    print(f"[+] TURN连接成功: {actual_server_address}")
                    return control_sock, nonce, realm, integrity_key, actual_server_address
            except Exception as e:
                print(f"[-] 连接TURN服务器失败 {server_address}: {e}")
                continue
        
        raise Exception("无法连接到任何TURN服务器")
    
    def scan_single_target(self, target_ip: str, ports: List[int], 
                          control_sock, nonce, realm, integrity_key, actual_server_address, 
                          output_file: str, results_dict: Dict) -> Dict:
        """使用已建立的TURN连接扫描单个目标IP的所有端口"""
        print(f"\n🎯 开始扫描目标: {target_ip}")
        print(f"📋 端口列表: {ports}")
        print("=" * 60)
        
        target_result = {
            'ip': target_ip,
            'scan_time': time.time(),
            'open_ports': [],
            'closed_ports': [],
            'errors': []
        }
        
        # 将目标结果添加到results_dict中
        results_dict[target_ip] = target_result
        
        try:
            # 扫描每个端口
            for port in ports:
                try:
                    print(f"\n[+] 扫描端口 {port}")
                    
                    # 创建权限
                    print(f"[+] 为 {target_ip}:{port} 创建权限")
                    if not create_permission(control_sock, nonce, realm, integrity_key, 
                                          target_ip, port, actual_server_address, self.username):
                        print(f"[-] 创建权限失败: {target_ip}:{port}")
                        target_result['errors'].append(f"权限创建失败: {port}")
                        # 立即保存结果
                        if output_file:
                            self._save_results_immediately(results_dict, output_file)
                        continue
                    
                    # 尝试TCP连接
                    print(f"[+] 尝试TCP连接到 {target_ip}:{port}")
                    if tcp_connect(control_sock, nonce, realm, integrity_key, 
                                target_ip, port, self.username):
                        print(f"✅ 端口 {port} 开放")
                        target_result['open_ports'].append({
                            'port': port,
                            'scan_time': time.time()
                        })
                    else:
                        print(f"❌ 端口 {port} 关闭")
                        target_result['closed_ports'].append(port)
                    
                    # 扫描完每个端口后立即保存结果
                    if output_file:
                        self._save_results_immediately(results_dict, output_file)
                        
                except Exception as e:
                    print(f"[-] 扫描端口 {port} 失败: {e}")
                    target_result['errors'].append(f"端口{port}: {str(e)}")
                    # 即使出错也要保存结果
                    if output_file:
                        self._save_results_immediately(results_dict, output_file)
                
        except Exception as e:
            print(f"[-] 扫描目标 {target_ip} 失败: {e}")
            target_result['errors'].append(f"扫描失败: {str(e)}")
            # 保存错误结果
            if output_file:
                self._save_results_immediately(results_dict, output_file)
        
        return target_result
    
    def _save_results_immediately(self, results_dict: Dict, output_file: str):
        """立即保存扫描结果到文件 - 清空文件重新写入字典"""
        try:
            with self.lock:
                # 清空文件
                with open(output_file, 'w', encoding='utf-8') as f:
                    pass
                # 重新写入字典
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results_dict, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[-] 保存结果失败: {e}")
    
    def batch_scan(self, targets: List[str], ports: List[int], max_workers: int = 5, output_file: str = None, reuse_connection: bool = False) -> List[Dict]:
        """批量扫描多个目标
        
        Args:
            reuse_connection: 如果为True，使用一个TURN连接扫描所有目标；如果为False，为每个目标建立新连接
        """
        mode_name = "连接复用模式 (单一TURN连接)" if reuse_connection else "独立连接模式 (每个目标独立TURN连接)"
        print("🚀 TURN代理批量TCP扫描器 (优化版)")
        print("=" * 60)
        print(f"TURN服务器: {self.turn_server}:{self.turn_port}")
        print(f"用户名: {self.username}")
        print(f"目标数量: {len(targets)}")
        print(f"端口数量: {len(ports)}")
        print(f"扫描模式: {mode_name}")
        print(f"使用TLS: {self.use_tls}")
        if output_file:
            print(f"实时保存: {output_file}")
        
        results_dict = {}
        
        if reuse_connection:
            # 复用模式：建立一个TURN连接，用于所有目标
            return self._batch_scan_with_reuse(targets, ports, output_file, results_dict)
        else:
            # 独立模式：每个目标建立新连接
            return self._batch_scan_with_new_connection(targets, ports, output_file, results_dict)
    
    def _batch_scan_with_reuse(self, targets: List[str], ports: List[int], output_file: str, results_dict: Dict):
        """连接复用模式：建立一个TURN连接，扫描所有目标"""
        control_sock = None
        try:
            # 建立一个TURN连接
            print(f"\n[+] 建立TURN连接（复用模式）...")
            control_sock, nonce, realm, integrity_key, actual_server_address = self.establish_turn_connection()
            print(f"[+] TURN连接建立成功，将扫描 {len(targets)} 个目标")
            
            # 用这个连接扫描所有目标
            for i, target in enumerate(targets, 1):
                print(f"\n📊 进度: {i}/{len(targets)} - 扫描目标: {target}")
                
                try:
                    result = self.scan_single_target(target, ports, 
                                                   control_sock, nonce, realm, integrity_key, actual_server_address,
                                                   output_file, results_dict)
                    print(f"✅ 完成扫描: {target} - 开放端口: {len(result['open_ports'])}")
                except Exception as e:
                    print(f"[-] 扫描目标 {target} 失败: {e}")
                    error_result = {
                        'ip': target,
                        'scan_time': time.time(),
                        'open_ports': [],
                        'closed_ports': [],
                        'errors': [f"扫描失败: {str(e)}"]
                    }
                    results_dict[target] = error_result
                    if output_file:
                        self._save_results_immediately(results_dict, output_file)
            
            # 关闭TURN连接
            if control_sock:
                control_sock.close()
                print("[+] TURN连接已关闭")
        except Exception as e:
            print(f"[-] TURN连接失败: {e}")
            # 记录所有目标失败
            for target in targets:
                error_result = {
                    'ip': target,
                    'scan_time': time.time(),
                    'open_ports': [],
                    'closed_ports': [],
                    'errors': [f"TURN连接失败: {str(e)}"]
                }
                results_dict[target] = error_result
            if output_file:
                self._save_results_immediately(results_dict, output_file)
        
        return list(results_dict.values())
    
    def _batch_scan_with_new_connection(self, targets: List[str], ports: List[int], output_file: str, results_dict: Dict):
        """独立连接模式：为每个目标建立新的TURN连接"""
        # 对每个目标都重新建立TURN连接
        for i, target in enumerate(targets, 1):
            print(f"\n📊 进度: {i}/{len(targets)} - 扫描目标: {target}")
            
            control_sock = None
            try:
                # 为每个目标建立新的TURN连接
                print(f"[+] 为目标 {target} 建立TURN连接...")
                control_sock, nonce, realm, integrity_key, actual_server_address = self.establish_turn_connection()
                print(f"[+] TURN连接建立成功")
                
                # 扫描单个目标
                try:
                    result = self.scan_single_target(target, ports, 
                                                   control_sock, nonce, realm, integrity_key, actual_server_address,
                                                   output_file, results_dict)
                    # result已经添加到results_dict中了
                    print(f"✅ 完成扫描: {target} - 开放端口: {len(result['open_ports'])}")
                except Exception as e:
                    print(f"[-] 扫描目标 {target} 失败: {e}")
                    error_result = {
                        'ip': target,
                        'scan_time': time.time(),
                        'open_ports': [],
                        'closed_ports': [],
                        'errors': [f"扫描失败: {str(e)}"]
                    }
                    results_dict[target] = error_result
                    # 保存错误结果
                    if output_file:
                        self._save_results_immediately(results_dict, output_file)
                
                # 关闭TURN连接
                if control_sock:
                    control_sock.close()
                    
            except Exception as e:
                print(f"[-] 建立TURN连接失败: {e}")
                error_result = {
                    'ip': target,
                    'scan_time': time.time(),
                    'open_ports': [],
                    'closed_ports': [],
                    'errors': [f"TURN连接失败: {str(e)}"]
                }
                results_dict[target] = error_result
                # 保存错误结果
                if output_file:
                    self._save_results_immediately(results_dict, output_file)
        
        # 将字典转换为列表返回（保持向后兼容）
        return list(results_dict.values())
    
    def save_results(self, results: List[Dict], output_file: str):
        """保存扫描结果到文件"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n💾 扫描结果已保存到: {output_file}")
    
    def print_summary(self, results: List[Dict]):
        """打印扫描结果汇总"""
        print("\n" + "=" * 60)
        print("📊 批量扫描结果汇总")
        print("=" * 60)
        
        total_targets = len(results)
        targets_with_open_ports = len([r for r in results if r['open_ports']])
        total_open_ports = sum(len(r['open_ports']) for r in results)
        
        print(f"总目标数: {total_targets}")
        print(f"有开放端口的目标: {targets_with_open_ports}")
        print(f"总开放端口数: {total_open_ports}")
        
        if targets_with_open_ports > 0:
            print(f"\n🎯 发现开放端口的目标:")
            for result in results:
                if result['open_ports']:
                    ports = [p['port'] for p in result['open_ports']]
                    print(f"  {result['ip']}: {ports}")
        
        if any(r['errors'] for r in results):
            print(f"\n⚠️ 扫描错误:")
            for result in results:
                if result['errors']:
                    print(f"  {result['ip']}: {len(result['errors'])} 个错误")

def main():
    parser = argparse.ArgumentParser(description="TURN代理批量TCP扫描器")
    parser.add_argument('--turn-server', required=True, help='TURN服务器地址')
    parser.add_argument('--turn-port', type=int, default=3478, help='TURN服务器端口')
    parser.add_argument('--username', required=True, help='TURN服务器用户名')
    parser.add_argument('--password', required=True, help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    parser.add_argument('--tls', action='store_true', help='使用TLS加密连接')
    parser.add_argument('--targets', 
                       help='目标IP列表 (例如: 192.168.1.1,192.168.1.2-192.168.1.10,192.168.2.0/24)')
    parser.add_argument('--targets-file', 
                       help='从文件读取目标IP列表 (每行一个IP或IP范围，支持注释#)')
    parser.add_argument('--ports', default='22,23,80,443,8080,8443,3389,5900,21,25,53,110,143,993,995',
                       help='端口列表 (例如: 80-443 或 80,443,8080)')
    parser.add_argument('--ports-file', 
                       help='从文件读取端口列表 (每行一个端口或端口范围，支持注释#)')
    parser.add_argument('--workers', type=int, default=1, help='线程数 (已优化为单线程顺序扫描)')
    parser.add_argument('--output', default='batch_turn_scan_results.json', help='输出文件路径')
    parser.add_argument('--reuse-connection', action='store_true', help='复用TURN连接模式：建立一个TURN连接扫描所有目标（快速，但可能受配额限制）')
    
    args = parser.parse_args()
    
    # 创建扫描器
    scanner = BatchTurnTcpScanner(
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tls=args.tls
    )
    
    try:
        # 解析目标和端口
        targets = []
        ports = []
        
        # 处理目标IP
        if args.targets_file:
            targets = scanner.parse_targets_from_file(args.targets_file)
            print(f"[+] 从文件读取到 {len(targets)} 个目标IP: {args.targets_file}")
        elif args.targets:
            targets = scanner.parse_targets(args.targets)
            print(f"[+] 解析到 {len(targets)} 个目标IP")
        else:
            print("[-] 必须指定 --targets 或 --targets-file")
            return
        
        # 处理端口
        if args.ports_file:
            ports = scanner.parse_ports_from_file(args.ports_file)
            print(f"[+] 从文件读取到 {len(ports)} 个端口: {args.ports_file}")
        else:
            ports = scanner.parse_ports(args.ports)
            print(f"[+] 解析到 {len(ports)} 个端口")
        
        if len(targets) > 50:
            print(f"⚠️ 目标数量较多 ({len(targets)})，建议减少目标数量或增加等待时间")
            response = input("是否继续? (y/N): ")
            if response.lower() != 'y':
                print("扫描已取消")
                return
        
        # 开始批量扫描
        start_time = time.time()
        results = scanner.batch_scan(targets, ports, args.workers, args.output, args.reuse_connection)
        end_time = time.time()
        
        # 保存结果（如果还没有实时保存的话）
        if not args.output:
            scanner.save_results(results, 'batch_turn_scan_results.json')
        
        # 打印汇总
        scanner.print_summary(results)
        
        print(f"\n⏱️ 总扫描时间: {end_time - start_time:.2f} 秒")
        
    except KeyboardInterrupt:
        print("\n[+] 用户中断扫描")
    except Exception as e:
        print(f"[-] 扫描失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
