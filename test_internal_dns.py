#!/usr/bin/env python3
"""
测试DNS服务器可以解析哪些内网域名
"""

import sys
import os
import time
import socket

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROTOCOL_DIR = os.path.join(CURRENT_DIR, "protocol_forwarding")

sys.path.insert(0, PROTOCOL_DIR)

from dns_turn_client import DNSTURNClient

# 常见的内网域名列表
INTERNAL_DOMAINS = [
    # Kubernetes 相关
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
    "kubernetes",
    
    # 常见服务
    "api",
    "api.default",
    "api.default.svc",
    "api.default.svc.cluster.local",
    
    # Docker/Kubernetes 服务发现
    "docker.internal",
    "host.docker.internal",
    "gateway.docker.internal",
    
    # 云服务内部域名
    "internal",
    "local",
    "localdomain",
    
    # Azure 相关
    "kubernetes.default.svc.cluster.local",
    
    # 常见服务名
    "nginx",
    "nginx.default",
    "nginx.default.svc",
    "nginx.default.svc.cluster.local",
    
    "redis",
    "redis.default",
    "redis.default.svc",
    
    "mysql",
    "mysql.default",
    "mysql.default.svc",
    
    "postgres",
    "postgres.default",
    "postgres.default.svc",
    
    # Ingress 相关
    "ingress-nginx",
    "ingress-nginx-controller",
    "ingress-nginx-controller.ingress-nginx",
    "ingress-nginx-controller.ingress-nginx.svc",
    "ingress-nginx-controller.ingress-nginx.svc.cluster.local",
    
    # 常见 Kubernetes 服务
    "kube-dns",
    "kube-dns.kube-system",
    "kube-dns.kube-system.svc",
    "kube-dns.kube-system.svc.cluster.local",
    
    "coredns",
    "coredns.kube-system",
    "coredns.kube-system.svc",
    "coredns.kube-system.svc.cluster.local",
    
    # Azure 元数据和管理服务
    "metadata.azure.com",
    "management.azure.com",
    "login.microsoftonline.com",
    
    # Azure Kubernetes Service (AKS) - 系统服务
    "tunnelfront.kube-system.svc.cluster.local",
    "tunnelfront.kube-system.svc",
    "tunnelfront.kube-system",
    
    "kube-proxy.kube-system.svc.cluster.local",
    "kube-proxy.kube-system.svc",
    "kube-proxy.kube-system",
    
    # Azure 私有 DNS 区域常见模式
    "internal",
    "local",
    "localdomain",
    
    # Azure 内部服务域名（常见后缀，不带通配符）
    "azurewebsites.net",
    "scm.azurewebsites.net",
    "azurecontainer.io",
    "servicebus.windows.net",
    "servicebus.azure.com",
    "blob.core.windows.net",
    "table.core.windows.net",
    "queue.core.windows.net",
    "file.core.windows.net",
    "database.windows.net",
    "database.secure.windows.net",
    "vault.azure.net",
    "vaultcore.azure.net",
    "privatelink.database.windows.net",
    "privatelink.blob.core.windows.net",
    "privatelink.servicebus.windows.net",
    "privatelink.azure.com",
    "azurecr.io",
    "visualstudio.com",
    "dev.azure.com",
    "cloudapp.net",
    "trafficmanager.net",
    "internal.cloudapp.net",
    "privatelink.azurewebsites.net",
]

def test_dns_resolution(dns_server_ip, dns_server_port, turn_server, turn_port, 
                       username, password, realm, use_tcp_udp=True, use_tls=True):
    """测试DNS服务器可以解析哪些内网域名"""
    
    print("="*70)
    print("🔍 测试内网域名解析")
    print("="*70)
    print(f"DNS Server: {dns_server_ip}:{dns_server_port}")
    print(f"TURN Server: {turn_server}:{turn_port}")
    print(f"测试域名数量: {len(INTERNAL_DOMAINS)}")
    print()
    
    # 创建DNS客户端
    dns_client = DNSTURNClient(
        dns_server_ip, 
        dns_server_port, 
        turn_server, 
        turn_port, 
        username, 
        password, 
        realm,
        use_tcp_udp=use_tcp_udp,
        use_tls=use_tls
    )
    
    try:
        # 建立连接
        if not dns_client.connect():
            print("[-] Failed to establish TURN connection")
            return
        
        print("[+] TURN connection established")
        print()
        
        # 统计结果
        resolved_domains = []
        failed_domains = []
        
        # 测试每个域名
        for i, domain in enumerate(INTERNAL_DOMAINS, 1):
            print(f"[{i}/{len(INTERNAL_DOMAINS)}] 测试: {domain}")
            
            # 为每个查询建立新连接（更可靠）
            try:
                # 断开旧连接
                dns_client.disconnect()
                # 建立新连接
                if not dns_client.connect():
                    print(f"    ❌ 连接失败")
                    failed_domains.append((domain, "Connection failed"))
                    continue
                
                # 执行查询
                result = dns_client.query_dns(domain, query_type=1)  # A记录
            except Exception as query_e:
                error_msg = str(query_e)
                print(f"    ❌ 错误: {error_msg}")
                failed_domains.append((domain, error_msg))
                result = None
            
            if result:
                if isinstance(result, dict) and result.get('answers'):
                    answers = result['answers']
                    ip_addresses = []
                    for answer in answers:
                        if answer.get('type') == 1:  # A记录
                            if len(answer.get('data', [])) == 4:
                                ip = '.'.join(str(b) for b in answer['data'])
                                ip_addresses.append(ip)
                    
                    if ip_addresses:
                        print(f"    ✅ 解析成功: {', '.join(ip_addresses)}")
                        resolved_domains.append((domain, ip_addresses))
                    else:
                        # 检查是否是 NXDOMAIN (Flags 0x8183)
                        flags = result.get('flags', 0)
                        if flags & 0x8003 == 0x8003:  # NXDOMAIN
                            print(f"    ⚠️  域名不存在 (NXDOMAIN)")
                            failed_domains.append((domain, "NXDOMAIN"))
                        else:
                            print(f"    ⚠️  收到响应但无A记录")
                            failed_domains.append((domain, "No A record"))
                else:
                    # 检查响应标志
                    flags = result.get('flags', 0) if isinstance(result, dict) else 0
                    if flags & 0x8003 == 0x8003:  # NXDOMAIN
                        print(f"    ⚠️  域名不存在 (NXDOMAIN)")
                        failed_domains.append((domain, "NXDOMAIN"))
                    else:
                        print(f"    ⚠️  收到响应但格式异常")
                        failed_domains.append((domain, "Invalid response"))
            else:
                print(f"    ❌ 查询失败")
                failed_domains.append((domain, "Query failed"))
            
            # 短暂延迟，避免请求过快
            time.sleep(0.3)
        
        # 打印总结
        print()
        print("="*70)
        print("📊 测试结果总结")
        print("="*70)
        print(f"成功解析: {len(resolved_domains)} 个域名")
        print(f"解析失败: {len(failed_domains)} 个域名")
        print()
        
        if resolved_domains:
            print("✅ 成功解析的域名:")
            for domain, ips in resolved_domains:
                print(f"  {domain:50} -> {', '.join(ips)}")
            print()
        
        if failed_domains:
            print("❌ 解析失败的域名:")
            for domain, reason in failed_domains[:20]:  # 只显示前20个
                print(f"  {domain:50} ({reason})")
            if len(failed_domains) > 20:
                print(f"  ... 还有 {len(failed_domains) - 20} 个域名解析失败")
        
    except KeyboardInterrupt:
        print("\n[+] 测试被用户中断")
    except Exception as e:
        print(f"[-] 测试出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        dns_client.disconnect()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='测试DNS服务器可以解析哪些内网域名')
    parser.add_argument('--dns-server', required=True, help='DNS服务器IP地址')
    parser.add_argument('--dns-port', type=int, default=53, help='DNS服务器端口 (默认: 53)')
    parser.add_argument('--turn-server', required=True, help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, required=True, help='TURN服务器端口')
    parser.add_argument('--username', required=True, help='TURN服务器用户名')
    parser.add_argument('--password', required=True, help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    parser.add_argument('--mode', choices=['udp', 'tcp-udp'], default='tcp-udp', 
                       help='TURN模式 (默认: tcp-udp)')
    parser.add_argument('--tls', action='store_true', help='使用TLS加密连接')
    
    args = parser.parse_args()
    
    test_dns_resolution(
        args.dns_server,
        args.dns_port,
        args.turn_server,
        args.turn_port,
        args.username,
        args.password,
        args.realm,
        use_tcp_udp=(args.mode == 'tcp-udp'),
        use_tls=args.tls
    )

