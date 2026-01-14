#!/usr/bin/env python3
"""
标准TURN服务器能力测试脚本
测试TURN服务器的TCP/UDP转发能力
"""

import argparse
import sys
import os
import socket
import struct
import time
import json
from datetime import datetime

# 添加路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'turn_utils'))
from turn_server_discovery import TURNServerDiscovery
from test_turn_capabilities import (
    test_udp_turn, test_tcp_udp_turn, test_tcp_turn,
    allocate_tcp_with_fallback, allocate_with_fallback, allocate_tcp_udp_with_fallback
)
from turn_client import (
    tcp_connect, create_permission, channel_bind, channel_data, channel_data_tcp,
    resolve_server_address, resolve_peer_address
)

class StandardAbilityTester:
    """标准TURN能力测试器"""
    
    def __init__(self, turn_server, turn_port, username, password, realm=None, use_tls=False):
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls
        
        # 发现服务器IP（如果域名解析出多个IP，取第一个）
        self.discovery = TURNServerDiscovery()
        self.server_ip = self._get_first_ip()
        
        if not self.server_ip:
            raise ValueError(f"无法解析TURN服务器地址: {turn_server}")
        
        print(f"[+] 使用TURN服务器IP: {self.server_ip}")
        
        # 测试目标
        self.tcp_public_targets = [
            ("1.1.1.1", 443),
            ("157.230.175.178", 80)
        ]
        self.tcp_internal_targets = [
            ("192.168.0.1", 443),
            ("172.17.0.1", 443),
            ("169.254.169.254", 80),
            ("10.233.0.1", 443),
            ("127.0.0.1",443)
        ]
        self.udp_public_targets = [
            ("8.8.8.8", 53),
            ("1.1.1.1", 53)
        ]
        self.udp_internal_targets = [
            ("192.168.0.1", 53),
            ("172.17.0.1", 53),
            ("10.233.0.1", 53),
            ("127.0.0.1",53)
        ]
    
    def _get_first_ip(self):
        """获取TURN服务器的第一个IP地址"""
        if self.discovery.is_ip_address(self.turn_server):
            return self.turn_server
        
        print(f"[+] 解析TURN服务器域名: {self.turn_server}")
        ips = self.discovery.discover_all_ips(self.turn_server, max_queries=10)
        if ips:
            ip_list = sorted(list(ips), key=lambda x: tuple(map(int, x.split('.'))))
            first_ip = ip_list[0]
            print(f"[+] 发现 {len(ip_list)} 个IP，使用第一个: {first_ip}")
            return first_ip
        return None
    
    def test_capabilities(self):
        """测试TURN服务器能力"""
        print("\n" + "="*60)
        print("🔍 测试TURN服务器能力")
        print("="*60)
        
        server_address = (self.server_ip, self.turn_port)
        capabilities = {}
        
        # 测试UDP
        print("\n[1/3] 测试UDP TURN...")
        try:
            result = test_udp_turn(
                server_address, self.username, self.password,
                self.realm, self.turn_server, "8.8.8.8", 53, False
            )
            capabilities['udp'] = result
        except Exception as e:
            print(f"  [-] UDP测试失败: {e}")
            capabilities['udp'] = False
        
        # 测试TCP+UDP
        print("\n[2/3] 测试TCP+UDP TURN...")
        try:
            result = test_tcp_udp_turn(
                server_address, self.username, self.password,
                self.realm, self.turn_server, self.use_tls, "8.8.8.8", 53, False
            )
            capabilities['tcp_udp'] = result
        except Exception as e:
            print(f"  [-] TCP+UDP测试失败: {e}")
            capabilities['tcp_udp'] = False
        
        # 测试TCP
        print("\n[3/3] 测试TCP TURN...")
        try:
            result = test_tcp_turn(
                server_address, self.username, self.password,
                self.realm, self.turn_server, self.use_tls, "httpbin.org", 80, False
            )
            capabilities['tcp'] = result
        except Exception as e:
            print(f"  [-] TCP测试失败: {e}")
            capabilities['tcp'] = False
        
        return capabilities
    
    def test_tcp_forwarding(self, targets, label):
        """测试TCP转发能力"""
        print(f"\n{'='*60}")
        print(f"🔍 测试TCP转发能力 - {label}")
        print(f"{'='*60}")
        
        server_address = (self.server_ip, self.turn_port)
        
        # 分配TCP TURN
        print("\n[1/2] 分配TCP TURN中继地址...")
        allocation_result, is_short_term = allocate_tcp_with_fallback(
            server_address, self.username, self.password, self.realm, self.use_tls
        )
        if not allocation_result:
            print("[-] TCP TURN分配失败")
            return []
        
        control_sock, nonce, realm, integrity_key, actual_server_address, *extra = allocation_result
        mi_algorithm = extra[0] if len(extra) > 0 else None
        
        results = []
        
        try:
            for target_ip, target_port in targets:
                print(f"\n[*] 测试目标: {target_ip}:{target_port}")
                
                # 创建权限
                peer_ip = resolve_peer_address(target_ip)
                if not peer_ip:
                    print(f"[-] 无法解析目标IP: {target_ip}")
                    results.append((target_ip, target_port, False, "无法解析IP"))
                    continue
                
                if not create_permission(
                    control_sock, nonce, realm, integrity_key,
                    peer_ip, target_port, actual_server_address, self.username, mi_algorithm
                ):
                    print(f"[-] 创建权限失败: {target_ip}:{target_port}")
                    results.append((target_ip, target_port, False, "创建权限失败"))
                    continue
                
                # 尝试TCP连接
                connection_id, error_info = tcp_connect(
                    control_sock, nonce, realm, integrity_key,
                    peer_ip, target_port, self.username, mi_algorithm
                )
                
                if connection_id:
                    print(f"[+] TCP连接成功: {target_ip}:{target_port}")
                    results.append((target_ip, target_port, True, "连接成功"))
                else:
                    error_msg = error_info.get('message', '未知错误') if error_info else '未知错误'
                    # 447错误和超时可能意味着服务器尝试连接但失败，这证明有转发能力
                    if '447' in error_msg or 'Timeout' in error_msg:
                        print(f"[!] TCP连接失败但服务器尝试转发: {target_ip}:{target_port} - {error_msg}")
                        results.append((target_ip, target_port, True, f"转发尝试({error_msg})"))
                    else:
                        print(f"[-] TCP连接失败: {target_ip}:{target_port} - {error_msg}")
                        results.append((target_ip, target_port, False, error_msg))
        
        finally:
            control_sock.close()
        
        return results
    
    def build_dns_query(self, domain="www.example.com", query_type=1):
        """构建DNS查询包"""
        transaction_id = int(time.time()) & 0xFFFF
        flags = 0x0100
        questions = 1
        header = struct.pack("!HHHHHH", transaction_id, flags, questions, 0, 0, 0)
        
        query_name = b""
        for part in domain.split('.'):
            query_name += struct.pack("!B", len(part)) + part.encode()
        query_name += b"\x00"
        
        query_type_class = struct.pack("!HH", query_type, 1)
        return header + query_name + query_type_class, transaction_id
    
    def parse_dns_response(self, data):
        """解析DNS响应"""
        if len(data) < 12:
            return None
        
        transaction_id, flags, questions, answer_rrs = struct.unpack("!HHHH", data[:8])
        return {
            'transaction_id': transaction_id,
            'flags': flags,
            'answers': answer_rrs
        }
    
    def test_udp_forwarding(self, targets, label, use_tcp_udp=False):
        """测试UDP转发能力（通过DNS查询）"""
        print(f"\n{'='*60}")
        print(f"🔍 测试UDP转发能力 - {label}")
        print(f"{'='*60}")
        
        server_address = (self.server_ip, self.turn_port)
        
        # 分配UDP或TCP+UDP TURN
        print(f"\n[1/3] 分配{'TCP+UDP' if use_tcp_udp else 'UDP'} TURN中继地址...")
        if use_tcp_udp:
            allocation_result, is_short_term = allocate_tcp_udp_with_fallback(
                server_address, self.username, self.password, self.realm,
                self.turn_server, self.use_tls
            )
        else:
            allocation_result, is_short_term = allocate_with_fallback(
                server_address, self.username, self.password, self.realm, self.turn_server
            )
        
        if not allocation_result:
            print(f"[-] {'TCP+UDP' if use_tcp_udp else 'UDP'} TURN分配失败")
            return []
        
        sock, nonce, realm, integrity_key, actual_server_address, *extra = allocation_result
        mi_algorithm = extra[0] if len(extra) > 0 else None
        
        results = []
        
        try:
            for idx, (target_ip, target_port) in enumerate(targets):
                # 在测试不同IP时增加1秒间隔（跳过第一个）
                if idx > 0:
                    time.sleep(1)
                
                print(f"\n[*] 测试目标: {target_ip}:{target_port}")
                
                # 创建权限
                peer_ip = resolve_peer_address(target_ip)
                if not peer_ip:
                    print(f"[-] 无法解析目标IP: {target_ip}")
                    results.append((target_ip, target_port, False, "无法解析IP"))
                    continue
                
                try:
                    if not create_permission(
                        sock, nonce, realm, integrity_key,
                        peer_ip, target_port, actual_server_address, self.username, mi_algorithm,
                        clear_buffer=use_tcp_udp  # 在TCP+UDP模式下清空缓冲区
                    ):
                        print(f"[-] 创建权限失败: {target_ip}:{target_port}")
                        results.append((target_ip, target_port, False, "创建权限失败"))
                        continue
                except (socket.timeout, AttributeError, OSError) as e:
                    # 在TCP+UDP模式下，create_permission可能因为socket类型问题失败
                    if use_tcp_udp:
                        print(f"[!] create_permission异常（TCP+UDP模式）: {e}")
                        print(f"[!] 跳过此目标，TCP+UDP模式下的create_permission需要修复")
                        results.append((target_ip, target_port, False, f"create_permission异常: {e}"))
                        continue
                    else:
                        raise
                
                # 绑定通道（为每个目标使用不同的通道号）
                import random
                channel_number = random.randint(0x4000, 0x4FFF)
                try:
                    # 在TCP+UDP模式下，channel_bind需要特殊处理
                    # 因为sock是TCP socket，但channel_bind可能误判为UDP
                    if use_tcp_udp:
                        # 临时设置超时，避免阻塞
                        original_timeout = sock.gettimeout()
                        sock.settimeout(10)
                        try:
                            # 尝试调用channel_bind，如果失败则手动处理
                            if not channel_bind(
                                sock, nonce, realm, integrity_key,
                                peer_ip, target_port, channel_number, actual_server_address,
                                self.username, mi_algorithm,
                                clear_buffer=use_tcp_udp  # 在TCP+UDP模式下清空缓冲区
                            ):
                                print(f"[-] 绑定通道失败: {target_ip}:{target_port}")
                                results.append((target_ip, target_port, False, "绑定通道失败"))
                                continue
                        except (socket.timeout, AttributeError, OSError) as e:
                            # 如果channel_bind因为socket类型问题失败，尝试手动处理
                            print(f"[!] channel_bind异常，尝试手动处理: {e}")
                            # 对于TCP+UDP，如果channel_bind失败，我们仍然可以尝试发送数据
                            # 因为某些服务器可能允许未绑定的通道
                            print(f"[!] 跳过通道绑定，直接尝试发送数据")
                        finally:
                            sock.settimeout(original_timeout)
                    else:
                        if not channel_bind(
                            sock, nonce, realm, integrity_key,
                            peer_ip, target_port, channel_number, actual_server_address,
                            self.username, mi_algorithm,
                            clear_buffer=use_tcp_udp  # 在TCP+UDP模式下清空缓冲区
                        ):
                            print(f"[-] 绑定通道失败: {target_ip}:{target_port}")
                            results.append((target_ip, target_port, False, "绑定通道失败"))
                            continue
                except Exception as e:
                    print(f"[-] 绑定通道异常: {target_ip}:{target_port} - {e}")
                    # 对于TCP+UDP，即使绑定失败也尝试发送数据
                    if not use_tcp_udp:
                        results.append((target_ip, target_port, False, f"绑定通道异常: {e}"))
                        continue
                    else:
                        print(f"[!] TCP+UDP模式下绑定失败，但继续尝试发送数据")
                
                # 发送DNS查询
                query_packet, transaction_id = self.build_dns_query()
                if use_tcp_udp:
                    if not channel_data_tcp(sock, channel_number, query_packet, actual_server_address):
                        results.append((target_ip, target_port, False, "发送DNS查询失败"))
                        continue
                else:
                    if not channel_data(sock, channel_number, query_packet, actual_server_address):
                        results.append((target_ip, target_port, False, "发送DNS查询失败"))
                        continue
                
                # 等待响应
                print(f"[+] DNS查询已发送，等待响应...")
                sock.settimeout(5)
                try:
                    if use_tcp_udp:
                        data = sock.recv(1024)
                    else:
                        data, addr = sock.recvfrom(1024)
                    
                    # 检查是否是ChannelData消息
                    if len(data) >= 4:
                        recv_channel = struct.unpack("!H", data[:2])[0]
                        data_length = struct.unpack("!H", data[2:4])[0]
                        
                        if recv_channel == channel_number and len(data) >= 4 + data_length:
                            dns_data = data[4:4+data_length]
                            dns_response = self.parse_dns_response(dns_data)
                            if dns_response:
                                print(f"[+] 收到DNS响应: {dns_response['answers']} 个答案")
                                results.append((target_ip, target_port, True, f"收到响应({dns_response['answers']}个答案)"))
                            else:
                                print(f"[+] 收到数据但解析失败")
                                results.append((target_ip, target_port, False, "DNS响应解析失败"))
                        else:
                            print(f"[+] 收到非预期的通道数据")
                            results.append((target_ip, target_port, False, "非预期的通道数据"))
                    else:
                        print(f"[+] 收到数据但长度不足")
                        results.append((target_ip, target_port, False, "数据长度不足"))
                
                except socket.timeout:
                    print(f"[!] 等待DNS响应超时（但查询可能已成功转发）")
                    # 超时不意味着失败，可能目标服务器没有响应或响应被过滤
                    results.append((target_ip, target_port, True, "查询已发送（超时无响应）"))
                except Exception as e:
                    print(f"[-] 接收响应错误: {e}")
                    results.append((target_ip, target_port, False, f"接收错误: {e}"))
        
        finally:
            sock.close()
        
        return results
    
    def run(self):
        """运行完整测试"""
        print("\n" + "="*60)
        print("🚀 标准TURN能力测试")
        print("="*60)
        print(f"TURN服务器: {self.turn_server}:{self.turn_port}")
        print(f"服务器IP: {self.server_ip}")
        print(f"用户名: {self.username}")
        print(f"使用TLS: {self.use_tls}")
        
        # 1. 测试能力
        capabilities = self.test_capabilities()
        
        print("\n" + "="*60)
        print("📊 能力测试结果")
        print("="*60)
        print(f"UDP: {capabilities.get('udp', False)}")
        print(f"TCP+UDP: {capabilities.get('tcp_udp', False)}")
        print(f"TCP: {capabilities.get('tcp', False)}")
        
        # 2. 测试TCP转发（如果有TCP能力）
        tcp_results = {}
        if capabilities.get('tcp', False):
            print("\n" + "="*60)
            print("🔍 测试TCP转发能力")
            print("="*60)
            
            # 公网测试
            public_results = self.test_tcp_forwarding(self.tcp_public_targets, "公网")
            tcp_results['public'] = public_results
            
            # 内网测试
            internal_results = self.test_tcp_forwarding(self.tcp_internal_targets, "内网")
            tcp_results['internal'] = internal_results
        else:
            print("\n[!] 服务器不支持TCP转发，跳过TCP测试")
        
        # 3. 测试UDP转发（如果有UDP或TCP+UDP能力）
        udp_results = {}
        has_udp = capabilities.get('udp', False)
        has_tcp_udp = capabilities.get('tcp_udp', False)
        
        if has_udp or has_tcp_udp:
            print("\n" + "="*60)
            print("🔍 测试UDP转发能力")
            print("="*60)
            
            # 优先使用UDP模式（更稳定），如果没有UDP则使用TCP+UDP
            use_tcp_udp = has_tcp_udp and not has_udp
            
            # 公网测试
            public_results = self.test_udp_forwarding(self.udp_public_targets, "公网", use_tcp_udp)
            udp_results['public'] = public_results
            
            # 内网测试
            internal_results = self.test_udp_forwarding(self.udp_internal_targets, "内网", use_tcp_udp)
            udp_results['internal'] = internal_results
        else:
            print("\n[!] 服务器不支持UDP转发，跳过UDP测试")
        
        # 4. 打印总结
        print("\n" + "="*60)
        print("📊 测试总结")
        print("="*60)
        
        if tcp_results:
            print("\nTCP转发测试:")
            print("  公网:")
            for ip, port, success, msg in tcp_results.get('public', []):
                status = "✓" if success else "✗"
                print(f"    {status} {ip}:{port} - {msg}")
            print("  内网:")
            for ip, port, success, msg in tcp_results.get('internal', []):
                status = "✓" if success else "✗"
                print(f"    {status} {ip}:{port} - {msg}")
        
        if udp_results:
            print("\nUDP转发测试:")
            print("  公网:")
            for ip, port, success, msg in udp_results.get('public', []):
                status = "✓" if success else "✗"
                print(f"    {status} {ip}:{port} - {msg}")
            print("  内网:")
            for ip, port, success, msg in udp_results.get('internal', []):
                status = "✓" if success else "✗"
                print(f"    {status} {ip}:{port} - {msg}")
        
        # 返回测试结果用于JSON输出
        return {
            'capabilities': capabilities,
            'tcp_results': tcp_results,
            'udp_results': udp_results
        }
    
    def save_results_to_json(self, domain, results, output_file='turn_test_results.json'):
        """将测试结果保存到JSON文件（追加模式）"""
        # 读取现有JSON文件
        existing_data = {}
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"[!] 读取现有JSON文件失败: {e}，将创建新文件")
                existing_data = {}
        
        # 准备要保存的数据
        result_data = {
            'timestamp': datetime.now().isoformat(),
            'server_info': {
                'turn_server': self.turn_server,
                'turn_port': self.turn_port,
                'server_ip': self.server_ip,
                'username': self.username,
                'use_tls': self.use_tls
            },
            'capabilities': results['capabilities'],
            'tcp_results': self._format_results_for_json(results['tcp_results']),
            'udp_results': self._format_results_for_json(results['udp_results'])
        }
        
        # 添加或更新domain对应的数据
        existing_data[domain] = result_data
        
        # 写回JSON文件
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)
            print(f"\n[+] 测试结果已保存到: {output_file} (domain: {domain})")
        except IOError as e:
            print(f"[-] 保存JSON文件失败: {e}")
    
    def _format_results_for_json(self, results):
        """将测试结果格式化为JSON友好的格式"""
        if not results:
            return {}
        
        formatted = {}
        for category in ['public', 'internal']:
            if category in results:
                formatted[category] = []
                for ip, port, success, msg in results[category]:
                    formatted[category].append({
                        'target_ip': ip,
                        'target_port': port,
                        'success': success,
                        'message': msg
                    })
        
        return formatted


def main():
    parser = argparse.ArgumentParser(description="标准TURN服务器能力测试")
    parser.add_argument("--turn-server", required=True, help="TURN服务器地址（域名或IP）")
    parser.add_argument("--turn-port", type=int, required=True, help="TURN服务器端口")
    parser.add_argument("--username", required=True, help="TURN用户名")
    parser.add_argument("--password", required=True, help="TURN密码")
    parser.add_argument("--realm", help="TURN认证域")
    parser.add_argument("--tls", action="store_true", help="使用TLS")
    parser.add_argument("--domain", required=True, help="域名标识（用作JSON输出中的key）")
    parser.add_argument("--output", default="turn_test_results.json", help="JSON输出文件路径（默认: turn_test_results.json）")
    
    args = parser.parse_args()
    
    try:
        tester = StandardAbilityTester(
            args.turn_server, args.turn_port,
            args.username, args.password, args.realm, args.tls
        )
        results = tester.run()
        tester.save_results_to_json(args.domain, results, args.output)
    except Exception as e:
        print(f"[-] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

