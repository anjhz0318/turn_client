#!/usr/bin/env python3
"""
TURN服务器发现工具
用于查询TURN服务器的所有IP地址
"""

import socket
import dns.resolver
import dns.exception
import time
import random
from typing import List, Set, Tuple
import argparse

class TURNServerDiscovery:
    """TURN服务器发现类"""
    
    def __init__(self):
        self.dns_servers = [
            '8.8.8.8',      # Google DNS
            '8.8.4.4',      # Google DNS
            '1.1.1.1',      # Cloudflare DNS
            '1.0.0.1',      # Cloudflare DNS
            '208.67.222.222', # OpenDNS
            '208.67.220.220', # OpenDNS
        ]
        self.discovered_ips = set()
    
    def is_ip_address(self, hostname: str) -> bool:
        """检查输入是否为IP地址"""
        try:
            socket.inet_aton(hostname)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, hostname)
                return True
            except socket.error:
                return False
        
    def resolve_with_socket(self, hostname: str) -> Set[str]:
        """使用socket.gethostbyname解析域名"""
        ips = set()
        try:
            ip = socket.gethostbyname(hostname)
            ips.add(ip)
            print(f"[+] Socket resolve {hostname} -> {ip}")
        except socket.gaierror as e:
            print(f"[-] Socket resolve failed for {hostname}: {e}")
        return ips
    
    def resolve_with_dns_query(self, hostname: str, dns_server: str = None) -> Set[str]:
        """使用dnspython库解析域名"""
        ips = set()
        
        try:
            # 创建DNS解析器
            resolver = dns.resolver.Resolver()
            if dns_server:
                resolver.nameservers = [dns_server]
            
            # 查询A记录
            answers = resolver.resolve(hostname, 'A')
            for answer in answers:
                ip = str(answer)
                ips.add(ip)
                print(f"[+] DNS query {hostname} -> {ip} (via {dns_server or 'default'})")
                
        except dns.exception.DNSException as e:
            print(f"[-] DNS query failed for {hostname} via {dns_server or 'default'}: {e}")
        
        return ips
    
    def resolve_with_multiple_dns(self, hostname: str, max_queries: int = 50) -> Set[str]:
        """使用多个DNS服务器多次查询获取所有可能的IP"""
        all_ips = set()
        
        print(f"[+] Starting multi-DNS resolution for {hostname}")
        print(f"[+] Using {len(self.dns_servers)} DNS servers with {max_queries} total queries")
        
        for i in range(max_queries):
            # 随机选择DNS服务器
            dns_server = random.choice(self.dns_servers)
            
            try:
                ips = self.resolve_with_dns_query(hostname, dns_server)
                all_ips.update(ips)
                
                # 添加延迟避免DNS限制
                time.sleep(0.1)
                
                # 每10次查询显示进度
                if (i + 1) % 10 == 0:
                    print(f"[+] Progress: {i + 1}/{max_queries} queries, found {len(all_ips)} unique IPs")
                    
            except Exception as e:
                print(f"[-] Query {i + 1} failed: {e}")
                continue
        
        return all_ips
    
    def resolve_with_system_dns(self, hostname: str, max_queries: int = 20) -> Set[str]:
        """使用系统DNS多次查询"""
        all_ips = set()
        
        print(f"[+] Starting system DNS resolution for {hostname}")
        
        for i in range(max_queries):
            try:
                # 使用socket解析
                ips = self.resolve_with_socket(hostname)
                all_ips.update(ips)
                
                # 添加随机延迟
                time.sleep(random.uniform(0.1, 0.5))
                
                # 每5次查询显示进度
                if (i + 1) % 5 == 0:
                    print(f"[+] Progress: {i + 1}/{max_queries} queries, found {len(all_ips)} unique IPs")
                    
            except Exception as e:
                print(f"[-] Query {i + 1} failed: {e}")
                continue
        
        return all_ips
    
    def discover_all_ips(self, hostname: str, max_queries: int = 100) -> Set[str]:
        """发现主机的所有IP地址"""
        print(f"=== TURN服务器IP发现: {hostname} ===")
        
        # 检查输入是否为IP地址
        if self.is_ip_address(hostname):
            print(f"[+] 输入是IP地址，直接返回: {hostname}")
            return {hostname}
        
        all_ips = set()
        
        # 1. 系统DNS解析
        print("\n[1] 使用系统DNS解析...")
        system_ips = self.resolve_with_system_dns(hostname, max_queries // 4)
        all_ips.update(system_ips)
        
        # 2. 多DNS服务器解析
        print(f"\n[2] 使用多个DNS服务器解析...")
        multi_dns_ips = self.resolve_with_multiple_dns(hostname, max_queries // 2)
        all_ips.update(multi_dns_ips)
        
        # 3. 单独测试每个DNS服务器
        print(f"\n[3] 单独测试每个DNS服务器...")
        for dns_server in self.dns_servers:
            print(f"[+] Testing DNS server: {dns_server}")
            dns_ips = self.resolve_with_dns_query(hostname, dns_server)
            all_ips.update(dns_ips)
            time.sleep(0.2)
        
        return all_ips
    
    def analyze_ips(self, ips: Set[str]) -> None:
        """分析发现的IP地址"""
        if not ips:
            print("[-] 没有发现任何IP地址")
            return
        
        print(f"\n=== 分析结果 ===")
        print(f"总共发现 {len(ips)} 个唯一的IP地址:")
        
        # 按IP地址排序
        ipv4_ips = [ip for ip in ips if '.' in ip]
        ipv6_ips = [ip for ip in ips if ':' in ip]
        
        # IPv4按数字排序
        sorted_ipv4 = sorted(ipv4_ips, key=lambda x: tuple(map(int, x.split('.'))))
        # IPv6按字符串排序
        sorted_ipv6 = sorted(ipv6_ips)
        
        sorted_ips = sorted_ipv4 + sorted_ipv6
        
        for i, ip in enumerate(sorted_ips, 1):
            print(f"  {i:2d}. {ip}")
        
        # 分析IP地址范围
        print(f"\n=== IP地址范围分析 ===")
        ipv4_ips = []
        ipv6_ips = []
        
        for ip in ips:
            if '.' in ip:  # IPv4
                ipv4_ips.append(ip)
            elif ':' in ip:  # IPv6
                ipv6_ips.append(ip)
        
        if ipv4_ips:
            print(f"IPv4地址 ({len(ipv4_ips)} 个):")
            ranges = {}
            for ip in ipv4_ips:
                parts = ip.split('.')
                range_key = f"{parts[0]}.{parts[1]}.{parts[2]}"
                if range_key not in ranges:
                    ranges[range_key] = []
                ranges[range_key].append(parts[3])
            
            for range_key, hosts in ranges.items():
                print(f"  {range_key}.x: {len(hosts)} 个主机 ({', '.join(sorted(hosts))})")
        
        if ipv6_ips:
            print(f"IPv6地址 ({len(ipv6_ips)} 个):")
            for ip in ipv6_ips:
                print(f"  {ip}")
    
    def test_turn_server(self, hostname: str, port: int = 3478, timeout: int = 5) -> List[Tuple[str, bool, str]]:
        """测试TURN服务器的连通性"""
        print(f"\n=== 测试TURN服务器连通性 ===")
        print(f"主机: {hostname}")
        print(f"端口: {port}")
        
        # 获取所有IP地址
        ips = self.discover_all_ips(hostname)
        results = []
        
        # 如果是IP地址，直接测试，不需要额外的发现过程
        if self.is_ip_address(hostname):
            print(f"[+] 输入是IP地址，直接测试连通性")
        
        if not ips:
            print("[-] 没有发现任何IP地址，无法测试连通性")
            return results
        
        print(f"\n[+] 测试 {len(ips)} 个IP地址的连通性...")
        
        for ip in sorted(ips, key=lambda x: tuple(map(int, x.split('.')))):
            try:
                # 创建socket连接测试
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                
                # 发送简单的UDP包测试连通性
                test_data = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\x00" * 12
                sock.sendto(test_data, (ip, port))
                
                # 尝试接收响应
                try:
                    response, addr = sock.recvfrom(1024)
                    results.append((ip, True, "响应正常"))
                    print(f"[+] {ip}:{port} - 连通 (响应: {len(response)} bytes)")
                except socket.timeout:
                    results.append((ip, True, "端口开放但无响应"))
                    print(f"[+] {ip}:{port} - 端口开放但无响应")
                
                sock.close()
                
            except socket.error as e:
                results.append((ip, False, str(e)))
                print(f"[-] {ip}:{port} - 不可达: {e}")
            
            time.sleep(0.1)
        
        return results

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='TURN服务器发现工具')
    parser.add_argument('hostname', help='TURN服务器主机名')
    parser.add_argument('--port', type=int, default=3478, help='TURN服务器端口 (默认: 3478)')
    parser.add_argument('--max-queries', type=int, default=100, help='最大查询次数 (默认: 100)')
    parser.add_argument('--test-connectivity', action='store_true', help='测试连通性')
    parser.add_argument('--timeout', type=int, default=5, help='连通性测试超时时间 (默认: 5秒)')
    
    args = parser.parse_args()
    
    # 创建发现工具
    discovery = TURNServerDiscovery()
    
    try:
        if args.test_connectivity:
            # 测试连通性
            results = discovery.test_turn_server(args.hostname, args.port, args.timeout)
            
            print(f"\n=== 连通性测试结果 ===")
            reachable = [r for r in results if r[1]]
            unreachable = [r for r in results if not r[1]]
            
            print(f"可到达: {len(reachable)}/{len(results)}")
            print(f"不可到达: {len(unreachable)}/{len(results)}")
            
            if reachable:
                print(f"\n可到达的服务器:")
                for ip, _, msg in reachable:
                    print(f"  {ip}:{args.port} - {msg}")
            
            if unreachable:
                print(f"\n不可到达的服务器:")
                for ip, _, msg in unreachable:
                    print(f"  {ip}:{args.port} - {msg}")
        else:
            # 仅发现IP地址
            ips = discovery.discover_all_ips(args.hostname, args.max_queries)
            discovery.analyze_ips(ips)
            
    except KeyboardInterrupt:
        print("\n[+] 用户中断")
    except Exception as e:
        print(f"[-] 错误: {e}")

if __name__ == "__main__":
    main()
