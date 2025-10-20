#!/usr/bin/env python3
"""
内网IP扫描脚本（低扰动版）

目标：在安全研究场景中尽可能减轻目标服务器负担。

策略：
- 单线程顺序扫描：避免并发对目标服务器造成过大压力
- 限速控制：每个请求之间添加延迟，控制扫描速度
- 采样控制：支持每网段最大扫描数量限制
- HTTP探测：发送简单的HTTP请求获取服务信息

用法：
python scan_internal_network.py --turn-server <TURN服务器地址> --turn-port <端口> --username <用户名> --password <密码> [--realm <认证域>] [--tls]
"""

import sys
import time
import socket
import ssl
import random
from http_turn_client import HTTPTURNClient

def write_result_to_file(output_file, result):
    """将单个扫描结果写入CSV文件"""
    try:
        # 提取SSL信息
        server = result.get('headers', {}).get('server', '')
        ssl_version = ''
        ssl_cipher = ''
        cert_cn = ''
        
        if result.get('ssl_info'):
            ssl_info = result['ssl_info']
            ssl_version = ssl_info.get('version', '')
            ssl_cipher = ssl_info.get('cipher', [''])[0] if ssl_info.get('cipher') else ''
            if ssl_info.get('peer_cert'):
                cert = ssl_info['peer_cert']
                subject = cert.get('subject', [])
                for item in subject:
                    if isinstance(item, tuple) and len(item) == 2:
                        if item[0] == 'commonName':
                            cert_cn = item[1]
                            break
        
        # 写入CSV行
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(f"{result['ip']},{result['port']},{result['success']},{result['status_code']},{result['content_length']},{server},{ssl_version},{ssl_cipher},{cert_cn},{result['error'] or ''}\n")
    except Exception as e:
        print(f"[!] 警告: 写入文件失败: {e}")

def generate_internal_ips(max_per_range: int = 256):
    """生成所有内网IP地址"""
    internal_ips = {}
    
    # RFC 1918 私有网络地址段
    private_ranges = [
        # 10.0.0.0/8
        ("10.0.0.0", "10.255.255.255"),
        # 172.16.0.0/12
        ("172.16.0.0", "172.31.255.255"),
        # 192.168.0.0/16
        ("192.168.0.0", "192.168.255.255"),
    ]
    
    print("[+] 生成内网IP地址（采样）...")
    
    for start_ip, end_ip in private_ranges:
        range_name = ""
        if start_ip.startswith("10."):
            range_name = "10.0.0.0/8"
        elif start_ip.startswith("172.16."):
            range_name = "172.16.0.0/12"
        elif start_ip.startswith("192.168."):
            range_name = "192.168.0.0/16"
        
        start_parts = [int(x) for x in start_ip.split('.')]
        end_parts = [int(x) for x in end_ip.split('.')]
        
        ips_in_range = []
        count = 0
        
        for a in range(start_parts[0], end_parts[0] + 1):
            for b in range(start_parts[1], end_parts[1] + 1):
                for c in range(start_parts[2], end_parts[2] + 1):
                    for d in range(start_parts[3], end_parts[3] + 1):
                        ip = f"{a}.{b}.{c}.{d}"
                        ips_in_range.append(ip)
                        count += 1
                        if count >= max_per_range:
                            break
                    if count >= max_per_range:
                        break
                if count >= max_per_range:
                    break
            if count >= max_per_range:
                break
        
        internal_ips[range_name] = ips_in_range
        print(f"[+] {range_name}: 采样 {len(ips_in_range)} 个IP地址")
    
    total_ips = sum(len(ips) for ips in internal_ips.values())
    print(f"[+] 总计生成 {total_ips} 个内网IP地址")
    
    return internal_ips

def scan_ip_range(ip_list, turn_server, turn_port, username, password, realm, use_tls, delay_seconds=1.0, max_successes=50, use_https=False, verify_ssl=True, ssl_context=None, output_file=None):
    """单线程顺序扫描IP范围"""
    results = []
    successes = 0
    
    # 初始化输出文件（如果指定）
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("IP,Port,Success,Status_Code,Content_Length,Server,SSL_Version,SSL_Cipher,Cert_CN,Error\n")
        print(f"[+] 输出文件已初始化: {output_file}")
    
    print(f"[+] 开始顺序扫描 {len(ip_list)} 个IP地址...")
    print(f"[+] 扫描延迟: {delay_seconds} 秒 | 最大成功数: {max_successes}")
    print(f"[+] HTTPS模式: {'启用' if use_https else '禁用'}")
    if use_https:
        print(f"[+] SSL验证: {'启用' if verify_ssl else '禁用'}")
    
    for i, ip in enumerate(ip_list):
        if successes >= max_successes:
            print(f"[+] 达到最大成功数阈值 ({max_successes})，停止扫描")
            break
        
        # 添加随机抖动
        jitter = random.uniform(0, 0.5)
        time.sleep(delay_seconds + jitter)
        
        # 根据HTTPS模式选择端口
        if use_https:
            ports = [443]  # 只扫描HTTPS端口
        else:
            ports = [80, 443]  # 扫描HTTP和HTTPS端口
        
        for port in ports:
            protocol = "HTTPS" if (use_https and port == 443) else "HTTP"
            print(f"[{i+1}/{len(ip_list)}] 测试 {ip}:{port} ({protocol})...", end=" ", flush=True)
            
            # 使用HTTPTURNClient.test_target静态方法
            result = HTTPTURNClient.test_target(
                turn_server=turn_server,
                turn_port=turn_port,
                turn_username=username,
                turn_password=password,
                turn_realm=realm,
                target_ip=ip,
                target_port=port,
                use_https=use_https and port == 443,
                verify_ssl=verify_ssl,
                use_tls=use_tls,
                server_hostname=turn_server
            )
            
            # 添加IP和端口信息到结果中
            result['ip'] = ip
            result['port'] = port
            results.append(result)
            
            # 立即写入输出文件（如果指定）
            if output_file:
                write_result_to_file(output_file, result)
            
            if result['success']:
                successes += 1
                status_info = f"{protocol} {result['status_code']}" if result['status_code'] else "Connected"
                content_info = f"({result['content_length']} bytes)" if result['content_length'] > 0 else ""
                print(f"✅ {status_info} {content_info}")
                
                # 显示服务器信息
                if result.get('headers', {}).get('server'):
                    print(f"    Server: {result['headers']['server']}")
                
                # 显示SSL信息
                if result.get('ssl_info'):
                    ssl_info = result['ssl_info']
                    print(f"    SSL: {ssl_info['version']} - {ssl_info['cipher'][0] if ssl_info['cipher'] else 'Unknown'}")
                    if ssl_info.get('peer_cert'):
                        cert = ssl_info['peer_cert']
                        subject = cert.get('subject', [])
                        if subject:
                            # 提取CN
                            for item in subject:
                                if isinstance(item, tuple) and len(item) == 2:
                                    if item[0] == 'commonName':
                                        print(f"    Cert: {item[1]}")
                                        break
                
                # 如果是HTTPS且响应较小，显示响应内容的前几行
                if use_https and port == 443 and result.get('response') and len(result['response']) < 2000:
                    print(f"\n    Response preview:")
                    response_lines = result['response'].split('\r\n')[:10]  # 只显示前10行
                    for line in response_lines:
                        if line.strip():
                            print(f"    {line}")
                    if len(result['response'].split('\r\n')) > 10:
                        print(f"    ... (truncated, total {len(result['response'])} chars)")
            else:
                print(f"❌ {result['error']}")
        
        # 每10个IP显示一次进度
        if (i + 1) % 10 == 0:
            print(f"[+] 进度: {i+1}/{len(ip_list)} ({successes} 成功)")
    
    return results

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='内网IP扫描脚本（低扰动版） - 通过TURN服务器单线程扫描')
    parser.add_argument('--turn-server', required=True, help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, default=3478, help='TURN服务器端口 (默认: 3478)')
    parser.add_argument('--username', required=True, help='TURN服务器用户名')
    parser.add_argument('--password', required=True, help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    parser.add_argument('--tls', action='store_true', help='使用TLS加密连接')
    parser.add_argument('--https', action='store_true', help='启用HTTPS扫描模式（只扫描443端口）')
    parser.add_argument('--no-verify-ssl', action='store_true', help='禁用SSL证书验证（用于测试环境）')
    parser.add_argument('--ssl-version', help='SSL版本 (TLSv1_2, TLSv1_3)')
    parser.add_argument('--ciphers', help='SSL加密套件（逗号分隔）')
    parser.add_argument('--delay', type=float, default=1.0, help='每个请求之间的延迟秒数 (默认: 1.0)')
    parser.add_argument('--max-successes', type=int, default=50, help='最大成功条目，达到后停止扫描 (默认: 50)')
    parser.add_argument('--max-per-range', type=int, default=256, help='每网段最多采样IP数量 (默认: 256)')
    parser.add_argument('--range', choices=['10', '172.16', '192.168', 'all'], default='all', 
                       help='扫描的IP范围 (默认: all)')
    parser.add_argument('--output', help='输出结果到文件')
    
    args = parser.parse_args()
    
    # 创建SSL上下文
    ssl_context = None
    if args.https and (args.ssl_version or args.ciphers):
        ssl_context = ssl.create_default_context()
        
        if not args.no_verify_ssl:
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        if args.ssl_version:
            try:
                if args.ssl_version.upper() == 'TLSV1_2':
                    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                    ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
                elif args.ssl_version.upper() == 'TLSV1_3':
                    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
                    ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
                print(f"[+] 使用SSL版本: {args.ssl_version}")
            except AttributeError:
                print(f"[-] SSL版本 {args.ssl_version} 不被此Python版本支持")
        
        if args.ciphers:
            ssl_context.set_ciphers(args.ciphers)
            print(f"[+] 使用SSL加密套件: {args.ciphers}")
    
    print("🔍 内网IP扫描工具（单线程低扰动版）")
    print("="*60)
    print(f"TURN服务器: {args.turn_server}:{args.turn_port}")
    print(f"用户名: {args.username}")
    print(f"认证域: {args.realm or '默认'}")
    print(f"使用TLS: {args.tls}")
    print(f"HTTPS模式: {args.https}")
    if args.https:
        print(f"SSL验证: {not args.no_verify_ssl}")
    print(f"扫描延迟: {args.delay} 秒")
    print(f"最大成功数: {args.max_successes}")
    print(f"扫描范围: {args.range}")
    
    # 生成内网IP
    internal_ips = generate_internal_ips(args.max_per_range)
    
    # 选择要扫描的IP范围
    if args.range == 'all':
        all_ips = []
        for range_name, ips in internal_ips.items():
            all_ips.extend(ips)
    elif args.range == '10':
        all_ips = internal_ips.get('10.0.0.0/8', [])
    elif args.range == '172.16':
        all_ips = internal_ips.get('172.16.0.0/12', [])
    elif args.range == '192.168':
        all_ips = internal_ips.get('192.168.0.0/16', [])
    
    if not all_ips:
        print("❌ 没有找到要扫描的IP地址")
        return
    
    print(f"[+] 准备扫描 {len(all_ips)} 个IP地址")
    
    # 开始扫描
    start_time = time.time()
    results = scan_ip_range(all_ips, args.turn_server, args.turn_port, args.username, args.password, args.realm, args.tls, args.delay, args.max_successes, args.https, not args.no_verify_ssl, ssl_context, args.output)
    end_time = time.time()
    
    # 统计结果
    successful = [r for r in results if r['success']]
    failed = [r for r in results if not r['success']]
    
    print("\n" + "="*60)
    print("📊 扫描结果汇总")
    print("="*60)
    print(f"总扫描IP数: {len(results)}")
    print(f"成功连接数: {len(successful)}")
    print(f"失败连接数: {len(failed)}")
    print(f"成功率: {len(successful)/len(results)*100:.1f}%")
    print(f"扫描耗时: {end_time - start_time:.1f} 秒")
    
    # 显示成功的连接
    if successful:
        print(f"\n✅ 发现 {len(successful)} 个可访问的服务:")
        for result in successful:
            protocol = "HTTPS" if result.get('ssl_info') else "HTTP"
            status_info = f"{protocol} {result['status_code']}" if result['status_code'] else "Connected"
            content_info = f"({result['content_length']} bytes)" if result['content_length'] > 0 else ""
            print(f"  {result['ip']}:{result['port']} - {status_info} {content_info}")
            if result.get('headers', {}).get('server'):
                print(f"    Server: {result['headers']['server']}")
            if result.get('ssl_info'):
                ssl_info = result['ssl_info']
                print(f"    SSL: {ssl_info['version']} - {ssl_info['cipher'][0] if ssl_info['cipher'] else 'Unknown'}")
                if ssl_info.get('peer_cert'):
                    cert = ssl_info['peer_cert']
                    subject = cert.get('subject', [])
                    if subject:
                        for item in subject:
                            if isinstance(item, tuple) and len(item) == 2:
                                if item[0] == 'commonName':
                                    print(f"    Cert: {item[1]}")
                                    break
    
    # 显示常见的失败原因
    if failed:
        error_counts = {}
        for result in failed:
            error = result['error'] or "Unknown error"
            error_counts[error] = error_counts.get(error, 0) + 1
        
        print(f"\n❌ 常见失败原因:")
        for error, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {error}: {count} 次")
    
    # 输出到文件信息
    if args.output:
        print(f"\n[+] 结果已实时保存到文件: {args.output}")

if __name__ == "__main__":
    main()