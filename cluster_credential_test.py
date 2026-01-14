#!/usr/bin/env python3
"""
测试集群中的TURN服务器
从clustered_by_realm.json或clustered_by_tls_domains.json中查找匹配的cluster，
并使用给定凭据测试所有或部分IP的端口申请能力
"""

import argparse
import json
import sys
import os
import random
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# 添加路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'turn_utils'))
from test_turn_capabilities import (
    allocate_with_fallback,
    allocate_tcp_with_fallback,
    allocate_tcp_udp_with_fallback
)


def load_cluster_data(input_file: str) -> Dict:
    """加载集群数据文件"""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[-] 文件不存在: {input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[-] JSON解析错误: {e}")
        sys.exit(1)


def find_matching_cluster(cluster_data: Dict, domain: str) -> Optional[Dict]:
    """查找与domain匹配的cluster"""
    # 精确匹配
    if domain in cluster_data:
        return cluster_data[domain]
    
    # 尝试通配符匹配（如果domain是通配符格式，如 *.example.com）
    if domain.startswith('*.'):
        base_domain = domain[2:]  # 去掉 '*.'
        for key in cluster_data.keys():
            if key.endswith('.' + base_domain) or key == base_domain:
                return cluster_data[key]
    
    # 尝试反向匹配（如果cluster key是通配符格式）
    for key in cluster_data.keys():
        if key.startswith('*.'):
            base = key[2:]
            if domain.endswith('.' + base) or domain == base:
                return cluster_data[key]
    
    return None


def test_allocation(server_ip: str, server_port: int, username: str, password: str, 
                   realm: Optional[str], use_tls: bool = False, sni_hostname: Optional[str] = None) -> Dict:
    """测试单个TURN服务器的端口申请能力"""
    server_address = (server_ip, server_port)
    result = {
        'ip': server_ip,
        'port': server_port,
        'timestamp': datetime.now().isoformat(),
        'udp': False,
        'tcp': False,
        'tcp_udp': False,
        'udp_error': None,
        'tcp_error': None,
        'tcp_udp_error': None
    }
    
    # 当端口为 443/5349（典型 TLS 端口）时，不测试纯UDP，仅测试 TCP / TCP+UDP
    if server_port in (443, 5349):
        result['udp'] = False
        result['udp_error'] = 'UDP test skipped for TLS port (443/5349)'
    else:
        # 测试UDP
        try:
            allocation_result, is_short_term = allocate_with_fallback(
                server_address, username, password, realm, None, use_tls
            )
            if allocation_result:
                result['udp'] = True
                # 关闭socket
                sock = allocation_result[0]
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
            else:
                result['udp_error'] = 'Allocation failed'
        except Exception as e:
            result['udp_error'] = str(e)
    
    # 测试TCP
    try:
        allocation_result, is_short_term = allocate_tcp_with_fallback(
            server_address, username, password, realm, use_tls, sni_hostname=sni_hostname
        )
        if allocation_result:
            result['tcp'] = True
            # 关闭socket
            sock = allocation_result[0]
            if sock:
                try:
                    sock.close()
                except:
                    pass
        else:
            result['tcp_error'] = 'Allocation failed'
    except Exception as e:
        result['tcp_error'] = str(e)
    
    # 测试TCP+UDP
    try:
        allocation_result, is_short_term = allocate_tcp_udp_with_fallback(
            server_address, username, password, realm, None, use_tls, sni_hostname=sni_hostname
        )
        if allocation_result:
            result['tcp_udp'] = True
            # 关闭socket
            sock = allocation_result[0]
            if sock:
                try:
                    sock.close()
                except:
                    pass
        else:
            result['tcp_udp_error'] = 'Allocation failed'
    except Exception as e:
        result['tcp_udp_error'] = str(e)
    
    return result


def test_cluster_servers(cluster_data: Dict, domain: str, server_port: int, 
                        username: str, password: str, realm: Optional[str],
                        mode: int, use_tls: bool = False, delay: float = 0.1,
                        max_workers: int = 20, sample_size: int = 100, 
                        sni_hostname: Optional[str] = None) -> List[Dict]:
    """测试cluster中的所有服务器（多线程，每个IP由一个线程处理一次）
    
    Args:
        mode: 1 = 测试所有 IP；2 = 随机抽样部分 IP（仅当 cluster 大小 > sample_size 时）
        sample_size: 模式2下随机测试的 IP 数量上限（默认 100）
    """
    cluster = find_matching_cluster(cluster_data, domain)
    
    if not cluster:
        print(f"[-] 未找到与domain '{domain}' 匹配的cluster")
        return []
    
    cluster_size = cluster.get('cluster_size', 0)
    ips = cluster.get('ips', [])
    
    if not ips:
        print(f"[-] Cluster '{domain}' 中没有IP地址")
        return []
    
    print(f"[+] 找到cluster: {domain}")
    print(f"[+] Cluster大小: {cluster_size} IPs")
    
    # 根据模式选择IP列表
    if mode == 2 and cluster_size > sample_size:
        selected_ips = random.sample(ips, sample_size)
        print(f"[+] 模式2：随机选择 {sample_size} 个IP进行测试（cluster大小: {cluster_size}）")
    else:
        selected_ips = ips
        if mode == 2:
            print(f"[!] Cluster大小 ({cluster_size}) 不超过 sample_size ({sample_size})，使用模式1（测试所有IP）")
        else:
            print(f"[+] 模式1：测试所有 {len(selected_ips)} 个IP")
    
    results: List[Optional[Dict]] = [None] * len(selected_ips)
    total = len(selected_ips)
    
    print(f"\n[+] 开始测试 {total} 个TURN服务器（多线程）...")
    print("=" * 70)

    # 限制最大线程数，避免在大集群时创建过多线程
    worker_count = max(1, min(max_workers, total))

    def worker(idx_ip: Tuple[int, str]):
        idx, ip = idx_ip
        print(f"\n[{idx}/{total}] 测试 {ip}:{server_port}")
        result = test_allocation(ip, server_port, username, password, realm, use_tls, sni_hostname)

        # 打印简要结果
        capabilities = []
        if result['udp']:
            capabilities.append('UDP')
        if result['tcp']:
            capabilities.append('TCP')
        if result['tcp_udp']:
            capabilities.append('TCP+UDP')

        if capabilities:
            print(f"    [+] 成功: {', '.join(capabilities)}")
        else:
            errors = []
            if result['udp_error']:
                errors.append(f"UDP: {result['udp_error']}")
            if result['tcp_error']:
                errors.append(f"TCP: {result['tcp_error']}")
            if result['tcp_udp_error']:
                errors.append(f"TCP+UDP: {result['tcp_udp_error']}")
            print(f"    [-] 失败: {', '.join(errors) if errors else 'All failed'}")

        # 轻微延迟，避免在极端情况下压垮本机/网络
        if delay > 0:
            time.sleep(delay)

        return idx, result

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(worker, (idx, ip))
            for idx, ip in enumerate(selected_ips, 1)
        ]
        for fut in as_completed(futures):
            idx, result = fut.result()
            results[idx - 1] = result

    # 类型断言：此时 results 中不应再有 None
    return [r for r in results if r is not None]


def save_results(domain: str, results: List[Dict], output_file: str, 
                server_port: int, username: str, password: str, realm: Optional[str]):
    """保存测试结果到JSON文件"""
    # 读取现有文件
    existing_data = {}
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing_data = {}
    
    # 准备结果数据
    result_data = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'test_config': {
            'server_port': server_port,
            'username': username,
            'realm': realm,
            'use_tls': False
        },
        'total_tested': len(results),
        'successful': {
            'udp': sum(1 for r in results if r.get('udp')),
            'tcp': sum(1 for r in results if r.get('tcp')),
            'tcp_udp': sum(1 for r in results if r.get('tcp_udp'))
        },
        'results': results
    }
    
    # 使用domain作为key，如果已存在则更新
    existing_data[domain] = result_data
    
    # 写回文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(existing_data, f, indent=2, ensure_ascii=False)
        print(f"\n[+] 结果已保存到: {output_file}")
    except IOError as e:
        print(f"[-] 保存文件失败: {e}")


def print_summary(results: List[Dict]):
    """打印测试总结"""
    total = len(results)
    if total == 0:
        return
    
    udp_success = sum(1 for r in results if r.get('udp'))
    tcp_success = sum(1 for r in results if r.get('tcp'))
    tcp_udp_success = sum(1 for r in results if r.get('tcp_udp'))
    
    print("\n" + "=" * 70)
    print("📊 测试总结")
    print("=" * 70)
    print(f"总测试数: {total}")
    print(f"UDP成功: {udp_success} ({udp_success/total*100:.1f}%)")
    print(f"TCP成功: {tcp_success} ({tcp_success/total*100:.1f}%)")
    print(f"TCP+UDP成功: {tcp_udp_success} ({tcp_udp_success/total*100:.1f}%)")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="测试集群中的TURN服务器端口申请能力",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
模式说明:
  模式1: 测试cluster中的所有IP
  模式2: 如果cluster大小超过100，随机选择100个IP进行测试；否则测试所有IP

示例:
  # 模式1：测试所有IP
  python3 test_cluster_turn_servers.py \\
    --input clustered_by_realm.json \\
    --domain rtcmedia \\
    --port 3478 \\
    --username demo \\
    --password demo123 \\
    --realm rtcmedia \\
    --mode 1

  # 模式2：随机测试部分IP（仅当cluster > sample_size时）
  python3 test_cluster_turn_servers.py \\
    --input clustered_by_tls_domains.json \\
    --domain "*.turn.teams.microsoft.com" \\
    --port 443 \\
    --username user \\
    --password pass \\
    --tls \\
    --mode 2 \\
    --sample-size 100
        """
    )
    
    parser.add_argument("--input", required=True,
                       help="输入文件路径 (clustered_by_realm.json 或 clustered_by_tls_domains.json)")
    parser.add_argument("--domain", required=True,
                       help="要查找的domain/realm名称")
    parser.add_argument("--port", type=int, required=True,
                       help="TURN服务器端口")
    parser.add_argument("--username", required=True,
                       help="TURN用户名")
    parser.add_argument("--password", required=True,
                       help="TURN密码")
    parser.add_argument("--realm",
                       help="TURN认证域（可选）")
    parser.add_argument("--tls", action="store_true",
                       help="使用TLS")
    parser.add_argument("--mode", type=int, choices=[1, 2], default=1,
                       help="测试模式: 1=测试所有IP, 2=随机抽样部分IP（仅当cluster>sample-size）")
    parser.add_argument("--output", default="cluster_turn_test_results.json",
                       help="输出JSON文件路径（默认: cluster_turn_test_results.json）")
    parser.add_argument("--delay", type=float, default=0.1,
                       help="每个请求之间的延迟（秒，默认: 0.1）")
    parser.add_argument("--sample-size", type=int, default=100,
                       help="模式2下随机测试的IP数量（默认: 100）")
    parser.add_argument("--max-workers", type=int, default=20,
                       help="最大并发线程数（默认: 20）")
    parser.add_argument("--sni", type=str, default=None,
                       help="TLS SNI主机名（用于TLS连接，默认使用服务器IP）")
    
    args = parser.parse_args()
    
    # 加载集群数据
    print(f"[+] 加载集群数据: {args.input}")
    cluster_data = load_cluster_data(args.input)
    print(f"[+] 已加载 {len(cluster_data)} 个clusters")
    
    # 测试服务器
    results = test_cluster_servers(
        cluster_data, args.domain, args.port,
        args.username, args.password, args.realm,
        args.mode, args.tls, args.delay,
        args.max_workers, args.sample_size, args.sni
    )
    
    if not results:
        print("[-] 没有测试结果")
        sys.exit(1)
    
    # 打印总结
    print_summary(results)
    
    # 保存结果
    save_results(
        args.domain, results, args.output,
        args.port, args.username, args.password, args.realm
    )


if __name__ == "__main__":
    main()

