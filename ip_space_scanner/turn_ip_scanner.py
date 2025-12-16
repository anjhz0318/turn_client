#!/usr/bin/env python3
"""
TURN服务器IP地址空间扫描工具
扫描互联网IPv4地址空间，发现TURN服务器

功能：
1. 向3478端口发送UDP TURN allocation请求
2. 向443和5349端口发送TCP TURN allocation请求（先尝试TLS，失败再尝试纯TCP）
3. 记录realm、banner、TLS证书域名信息
4. 如果发现TURN服务器，查询rDNS和whois信息
5. 支持单IP测试和全IPv4扫描模式
6. 多线程支持
"""

import argparse
import json
import socket
import ssl
import struct
import threading
import time
import queue
import csv
import tempfile
from datetime import datetime
from typing import Dict, Optional, Tuple, List
import sys
import os

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'turn_utils'))

from turn_utils.turn_client import (
    STUN_ALLOCATE_REQUEST, STUN_ALLOCATE_SUCCESS_RESPONSE, STUN_ALLOCATE_ERROR_RESPONSE,
    STUN_ATTR_REALM, STUN_ATTR_NONCE, STUN_ATTR_ERROR_CODE, STUN_ATTR_REQUESTED_TRANSPORT,
    STUN_ATTR_USERNAME,
    gen_tid, parse_attrs, stun_attr, build_msg_with_short_term_credential,
    build_msg, compute_long_term_hmac_key, opaque_string
)

# STUN属性类型
STUN_ATTR_SOFTWARE = 0x8022  # SOFTWARE属性（banner信息）

class TURNIPScanner:
    """TURN IP扫描器"""
    
    def __init__(self, output_file: str = "turn_scan_results.json", threads: int = 10):
        self.output_file = output_file
        self.threads = threads
        self.results = self._load_results()
        self.lock = threading.Lock()
        self.scan_count = 0
        self.found_count = 0
        
    def _load_results(self) -> Dict:
        """加载已有结果（从JSON文件读取字典，key是IP地址）"""
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    results = json.load(f)
                    # 确保返回的是字典格式（key是IP地址）
                    if isinstance(results, dict):
                        return results
                    else:
                        print(f"[-] 结果文件格式错误，期望字典格式", flush=True)
                        return {}
            except Exception as e:
                print(f"[-] 无法加载结果文件: {e}", flush=True)
        return {}
    
    def _save_results(self):
        """保存结果到文件（增量更新模式，原子操作）"""
        try:
            # 先读取现有文件（如果存在），然后update，再保存
            existing_results = {}
            if os.path.exists(self.output_file):
                try:
                    with open(self.output_file, 'r') as f:
                        existing_results = json.load(f)
                except:
                    # 如果读取失败，使用空字典
                    existing_results = {}
            
            # 将当前结果update到现有结果中
            existing_results.update(self.results)
            
            # 确保所有数据都是JSON可序列化的
            serializable_results = make_json_serializable(existing_results)
            
            # 原子写入：先写入临时文件，然后原子性地重命名
            temp_file = self.output_file + '.tmp'
            try:
                # 写入临时文件
                with open(temp_file, 'w') as f:
                    json.dump(serializable_results, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())  # 确保数据写入磁盘
                
                # 原子性地替换原文件（在POSIX系统上，rename是原子操作）
                os.replace(temp_file, self.output_file)
            except Exception as e:
                # 如果写入失败，删除临时文件
                if os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except:
                        pass
                raise e
        except Exception as e:
            print(f"[-] 保存结果失败: {e}", flush=True)
    
    def _update_last_scanned_ip(self, ip: str):
        """更新最后扫描的IP地址（线程安全，增量更新模式，原子操作）"""
        try:
            with self.lock:
                # 在结果文件中添加元数据字段（使用特殊前缀避免与IP地址冲突）
                if '_metadata' not in self.results:
                    self.results['_metadata'] = {}
                self.results['_metadata']['last_scanned_ip'] = ip
                self.results['_metadata']['last_scan_timestamp'] = datetime.now().isoformat()
                
                # 先读取现有文件，然后update，再保存
                existing_results = {}
                if os.path.exists(self.output_file):
                    try:
                        with open(self.output_file, 'r') as f:
                            existing_results = json.load(f)
                    except:
                        existing_results = {}
                
                # 将当前结果update到现有结果中
                existing_results.update(self.results)
                
                # 确保所有数据都是JSON可序列化的
                serializable_results = make_json_serializable(existing_results)
                
                # 原子写入：先写入临时文件，然后原子性地重命名
                temp_file = self.output_file + '.tmp'
                try:
                    # 写入临时文件
                    with open(temp_file, 'w') as f:
                        json.dump(serializable_results, f, indent=2)
                        f.flush()
                        os.fsync(f.fileno())  # 确保数据写入磁盘
                    
                    # 原子性地替换原文件
                    os.replace(temp_file, self.output_file)
                except Exception as e:
                    # 如果写入失败，删除临时文件
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                        except:
                            pass
                    raise e
        except Exception as e:
            print(f"[!] 更新最后扫描IP失败: {e}", flush=True)
    
    def _ip_to_int(self, ip: str) -> int:
        """将IP地址转换为整数（用于比较）"""
        parts = ip.split('.')
        return int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3])
    
    def _int_to_ip(self, ip_int: int) -> str:
        """将整数转换为IP地址"""
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
    
    def _get_last_scanned_ip(self) -> Optional[str]:
        """获取最后扫描的IP地址"""
        if '_metadata' in self.results:
            return self.results['_metadata'].get('last_scanned_ip')
        return None
    
    def _extract_realm(self, attrs: Dict) -> Optional[str]:
        """从响应属性中提取realm"""
        if STUN_ATTR_REALM in attrs:
            try:
                return attrs[STUN_ATTR_REALM].decode('utf-8', errors='ignore').rstrip('\x00')
            except:
                return None
        return None
    
    def _extract_banner(self, attrs: Dict) -> Optional[str]:
        """从响应属性中提取banner（SOFTWARE属性）"""
        if STUN_ATTR_SOFTWARE in attrs:
            try:
                return attrs[STUN_ATTR_SOFTWARE].decode('utf-8', errors='ignore').rstrip('\x00')
            except:
                return None
        return None
    
    def _extract_error_message(self, attrs: Dict) -> Optional[str]:
        """从错误响应中提取错误消息"""
        if STUN_ATTR_ERROR_CODE in attrs:
            error_code = attrs[STUN_ATTR_ERROR_CODE]
            if len(error_code) >= 4:
                error_class = error_code[2]
                error_number = error_code[3]
                error_reason = error_code[4:].decode('utf-8', errors='ignore') if len(error_code) > 4 else ""
                return f"{error_class}{error_number:02d} {error_reason}"
        return None
    
    def _test_udp_turn(self, ip: str, port: int = 3478) -> Optional[Dict]:
        """测试UDP TURN allocation（先尝试长期凭据，失败再尝试短期凭据）"""
        result = {
            'port': port,
            'protocol': 'UDP',
            'success': False,
            'realm': None,
            'banner': None,
            'error': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            
            username = "test"
            password = "test"
            
            # 第一步：尝试长期凭据（发送无认证请求）
            tid1 = gen_tid()
            req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))
            ])
            sock.sendto(req1, (ip, port))
            data1, _ = sock.recvfrom(2000)
            msg_type1, _, resp_attrs1 = parse_attrs(data1)
            
            # 提取realm和banner（从第一次响应中）
            result['realm'] = self._extract_realm(resp_attrs1)
            result['banner'] = self._extract_banner(resp_attrs1)
            
            # 如果是401错误，尝试第二次请求（带认证）
            if msg_type1 == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = resp_attrs1.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    if error_class == 4 and error_number == 1:  # 401
                        nonce = resp_attrs1.get(STUN_ATTR_NONCE)
                        server_realm = resp_attrs1.get(STUN_ATTR_REALM)
                        if nonce and server_realm:
                            # 发送第二次请求（带长期凭据认证）
                            tid2 = gen_tid()
                            integrity_key = compute_long_term_hmac_key(username, server_realm, password)
                            attrs2 = [
                                stun_attr(STUN_ATTR_USERNAME, username.encode()),
                                stun_attr(STUN_ATTR_REALM, server_realm),
                                stun_attr(STUN_ATTR_NONCE, nonce),
                                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),
                            ]
                            req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
                            sock.sendto(req2, (ip, port))
                            data2, _ = sock.recvfrom(2000)
                            msg_type2, _, resp_attrs2 = parse_attrs(data2)
                            
                            # 更新结果
                            result['success'] = msg_type2 == STUN_ALLOCATE_SUCCESS_RESPONSE
                            if not result['realm']:
                                result['realm'] = self._extract_realm(resp_attrs2)
                            if not result['banner']:
                                result['banner'] = self._extract_banner(resp_attrs2)
                            if msg_type2 == STUN_ALLOCATE_ERROR_RESPONSE:
                                error_code2 = resp_attrs2.get(STUN_ATTR_ERROR_CODE)
                                if error_code2:
                                    error_class2 = error_code2[2]
                                    error_number2 = error_code2[3]
                                    # 如果是400错误，尝试短期凭据
                                    if error_class2 == 4 and error_number2 == 0:
                                        # 回退为短期凭据
                                        integrity_key_short = opaque_string(password)
                                        attrs_short = [
                                            stun_attr(STUN_ATTR_USERNAME, username.encode()),
                                            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),
                                        ]
                                        tid_short = gen_tid()
                                        req_short = build_msg_with_short_term_credential(STUN_ALLOCATE_REQUEST, tid_short, attrs_short, integrity_key_short, add_fingerprint=True)
                                        sock.sendto(req_short, (ip, port))
                                        data_short, _ = sock.recvfrom(2000)
                                        msg_type_short, _, resp_attrs_short = parse_attrs(data_short)
                                        
                                        result['success'] = msg_type_short == STUN_ALLOCATE_SUCCESS_RESPONSE
                                        if not result['realm']:
                                            result['realm'] = self._extract_realm(resp_attrs_short)
                                        if not result['banner']:
                                            result['banner'] = self._extract_banner(resp_attrs_short)
                                        result['error'] = self._extract_error_message(resp_attrs_short) if msg_type_short == STUN_ALLOCATE_ERROR_RESPONSE else None
                                    else:
                                        result['error'] = self._extract_error_message(resp_attrs2)
                                else:
                                    result['error'] = self._extract_error_message(resp_attrs2)
                            else:
                                result['error'] = None
                        else:
                            result['error'] = self._extract_error_message(resp_attrs1)
                    else:
                        result['error'] = self._extract_error_message(resp_attrs1)
                else:
                    result['error'] = self._extract_error_message(resp_attrs1)
            elif msg_type1 == STUN_ALLOCATE_SUCCESS_RESPONSE:
                result['success'] = True
                result['error'] = None
            else:
                result['error'] = f"Unexpected response type: 0x{msg_type1:04x}"
            
            sock.close()
            return result
            
        except socket.timeout:
            return None
        except Exception as e:
            result['error'] = str(e)
            return result
    
    def _test_tcp_turn(self, ip: str, port: int, use_tls: bool = True) -> Optional[Dict]:
        """测试TCP TURN allocation（先尝试TLS，失败再尝试纯TCP）"""
        result = {
            'port': port,
            'protocol': 'TCP',
            'tls': use_tls,
            'success': False,
            'realm': None,
            'banner': None,
            'tls_cert_domains': None,
            'error': None
        }
        
        try:
            # 先尝试TLS（如果指定）
            if use_tls:
                try:
                    tls_result = self._test_tcp_turn_with_tls(ip, port)
                    if tls_result:
                        return tls_result
                except Exception as e:
                    # TLS失败，尝试纯TCP
                    pass
            
            # 尝试纯TCP
            return self._test_tcp_turn_plain(ip, port)
            
        except Exception as e:
            result['error'] = str(e)
            return result
    
    def _test_tcp_turn_with_tls(self, ip: str, port: int) -> Optional[Dict]:
        """测试TCP TURN allocation with TLS"""
        result = {
            'port': port,
            'protocol': 'TCP',
            'tls': True,
            'success': False,
            'realm': None,
            'banner': None,
            'tls_cert_domains': None,
            'error': None
        }
        
        try:
            # 建立TCP连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            # 建立TLS连接
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            tls_sock = context.wrap_socket(sock, server_hostname=ip)
            
            # 提取TLS证书域名
            cert_domains = []
            try:
                # 先尝试获取字典格式证书
                cert = tls_sock.getpeercert(binary_form=False)
                if cert and cert != {}:  # 检查不是空字典
                    # 提取Subject Alternative Name (SAN)
                    for key, value in cert.get('subjectAltName', []):
                        if key == 'DNS':
                            cert_domains.append(value)
                    # 提取Common Name (CN)
                    for item in cert.get('subject', []):
                        for key, value in item:
                            if key == 'commonName':
                                cert_domains.append(value)
                
                # 如果字典格式为空，尝试二进制格式并使用cryptography库解析
                if not cert_domains:
                    cert_binary = tls_sock.getpeercert(binary_form=True)
                    if cert_binary:
                        try:
                            from cryptography import x509
                            from cryptography.hazmat.backends import default_backend
                            cert_obj = x509.load_der_x509_certificate(cert_binary, default_backend())
                            
                            # 提取SAN
                            try:
                                san_ext = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                for alt in san_ext.value:
                                    if hasattr(alt, 'value'):
                                        cert_domains.append(alt.value)
                            except:
                                pass
                            
                            # 提取CN
                            for attr in cert_obj.subject:
                                if attr.oid._name == 'commonName':
                                    cert_domains.append(attr.value)
                        except ImportError:
                            pass  # cryptography库不可用
                        except Exception:
                            pass  # 解析失败
            except Exception:
                pass  # 获取证书失败
            
            # 发送TURN allocation请求（先尝试长期凭据）
            username = "test"
            password = "test"
            
            # 第一步：发送无认证请求（长期凭据的第一步）
            tid1 = gen_tid()
            req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00"))
            ])
            tls_sock.sendall(req1)
            
            # 接收第一次响应
            data1 = b''
            tls_sock.settimeout(3)
            while len(data1) < 20:
                chunk = tls_sock.recv(2000)
                if not chunk:
                    break
                data1 += chunk
                if len(data1) >= 20:
                    msg_len = struct.unpack("!H", data1[2:4])[0]
                    expected_len = 20 + msg_len
                    if len(data1) >= expected_len:
                        break
            
            msg_type1, _, resp_attrs1 = parse_attrs(data1)
            
            # 提取realm和banner
            result['realm'] = self._extract_realm(resp_attrs1)
            result['banner'] = self._extract_banner(resp_attrs1)
            result['tls_cert_domains'] = list(set(cert_domains)) if cert_domains else None
            
            # 如果是401错误，尝试第二次请求（带认证）
            if msg_type1 == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = resp_attrs1.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    if error_class == 4 and error_number == 1:  # 401
                        nonce = resp_attrs1.get(STUN_ATTR_NONCE)
                        server_realm = resp_attrs1.get(STUN_ATTR_REALM)
                        if nonce and server_realm:
                            # 发送第二次请求（带长期凭据认证）
                            tid2 = gen_tid()
                            integrity_key = compute_long_term_hmac_key(username, server_realm, password)
                            attrs2 = [
                                stun_attr(STUN_ATTR_USERNAME, username.encode()),
                                stun_attr(STUN_ATTR_REALM, server_realm),
                                stun_attr(STUN_ATTR_NONCE, nonce),
                                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00")),
                            ]
                            req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
                            tls_sock.sendall(req2)
                            
                            # 接收第二次响应
                            data2 = b''
                            while len(data2) < 20:
                                chunk = tls_sock.recv(2000)
                                if not chunk:
                                    break
                                data2 += chunk
                                if len(data2) >= 20:
                                    msg_len = struct.unpack("!H", data2[2:4])[0]
                                    expected_len = 20 + msg_len
                                    if len(data2) >= expected_len:
                                        break
                            
                            msg_type2, _, resp_attrs2 = parse_attrs(data2)
                            
                            result['success'] = msg_type2 == STUN_ALLOCATE_SUCCESS_RESPONSE
                            if not result['realm']:
                                result['realm'] = self._extract_realm(resp_attrs2)
                            if not result['banner']:
                                result['banner'] = self._extract_banner(resp_attrs2)
                            
                            if msg_type2 == STUN_ALLOCATE_ERROR_RESPONSE:
                                error_code2 = resp_attrs2.get(STUN_ATTR_ERROR_CODE)
                                if error_code2:
                                    error_class2 = error_code2[2]
                                    error_number2 = error_code2[3]
                                    # 如果是400错误，尝试短期凭据
                                    if error_class2 == 4 and error_number2 == 0:
                                        integrity_key_short = opaque_string(password)
                                        attrs_short = [
                                            stun_attr(STUN_ATTR_USERNAME, username.encode()),
                                            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00")),
                                        ]
                                        tid_short = gen_tid()
                                        req_short = build_msg_with_short_term_credential(STUN_ALLOCATE_REQUEST, tid_short, attrs_short, integrity_key_short, add_fingerprint=True)
                                        tls_sock.sendall(req_short)
                                        
                                        data_short = b''
                                        while len(data_short) < 20:
                                            chunk = tls_sock.recv(2000)
                                            if not chunk:
                                                break
                                            data_short += chunk
                                            if len(data_short) >= 20:
                                                msg_len = struct.unpack("!H", data_short[2:4])[0]
                                                expected_len = 20 + msg_len
                                                if len(data_short) >= expected_len:
                                                    break
                                        
                                        msg_type_short, _, resp_attrs_short = parse_attrs(data_short)
                                        result['success'] = msg_type_short == STUN_ALLOCATE_SUCCESS_RESPONSE
                                        if not result['realm']:
                                            result['realm'] = self._extract_realm(resp_attrs_short)
                                        if not result['banner']:
                                            result['banner'] = self._extract_banner(resp_attrs_short)
                                        result['error'] = self._extract_error_message(resp_attrs_short) if msg_type_short == STUN_ALLOCATE_ERROR_RESPONSE else None
                                    else:
                                        result['error'] = self._extract_error_message(resp_attrs2)
                                else:
                                    result['error'] = self._extract_error_message(resp_attrs2)
                            else:
                                result['error'] = None
                        else:
                            result['error'] = self._extract_error_message(resp_attrs1)
                    else:
                        result['error'] = self._extract_error_message(resp_attrs1)
                else:
                    result['error'] = self._extract_error_message(resp_attrs1)
            elif msg_type1 == STUN_ALLOCATE_SUCCESS_RESPONSE:
                result['success'] = True
                result['error'] = None
            else:
                result['error'] = f"Unexpected response type: 0x{msg_type1:04x}"
            
            tls_sock.close()
            return result
            
        except ssl.SSLError:
            # TLS握手失败，返回None让调用者尝试纯TCP
            return None
        except socket.timeout:
            return None
        except Exception as e:
            result['error'] = str(e)
            return result
    
    def _test_tcp_turn_plain(self, ip: str, port: int) -> Optional[Dict]:
        """测试纯TCP TURN allocation（无TLS）"""
        result = {
            'port': port,
            'protocol': 'TCP',
            'tls': False,
            'success': False,
            'realm': None,
            'banner': None,
            'tls_cert_domains': None,
            'error': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            username = "test"
            password = "test"
            
            # 第一步：发送无认证请求（长期凭据的第一步）
            tid1 = gen_tid()
            req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00"))
            ])
            sock.sendall(req1)
            
            # 接收第一次响应
            data1 = b''
            sock.settimeout(3)
            while len(data1) < 20:
                chunk = sock.recv(2000)
                if not chunk:
                    break
                data1 += chunk
                if len(data1) >= 20:
                    msg_len = struct.unpack("!H", data1[2:4])[0]
                    expected_len = 20 + msg_len
                    if len(data1) >= expected_len:
                        break
            
            msg_type1, _, resp_attrs1 = parse_attrs(data1)
            
            # 提取realm和banner
            result['realm'] = self._extract_realm(resp_attrs1)
            result['banner'] = self._extract_banner(resp_attrs1)
            
            # 如果是401错误，尝试第二次请求（带认证）
            if msg_type1 == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = resp_attrs1.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    if error_class == 4 and error_number == 1:  # 401
                        nonce = resp_attrs1.get(STUN_ATTR_NONCE)
                        server_realm = resp_attrs1.get(STUN_ATTR_REALM)
                        if nonce and server_realm:
                            # 发送第二次请求（带长期凭据认证）
                            tid2 = gen_tid()
                            integrity_key = compute_long_term_hmac_key(username, server_realm, password)
                            attrs2 = [
                                stun_attr(STUN_ATTR_USERNAME, username.encode()),
                                stun_attr(STUN_ATTR_REALM, server_realm),
                                stun_attr(STUN_ATTR_NONCE, nonce),
                                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00")),
                            ]
                            req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
                            sock.sendall(req2)
                            
                            # 接收第二次响应
                            data2 = b''
                            while len(data2) < 20:
                                chunk = sock.recv(2000)
                                if not chunk:
                                    break
                                data2 += chunk
                                if len(data2) >= 20:
                                    msg_len = struct.unpack("!H", data2[2:4])[0]
                                    expected_len = 20 + msg_len
                                    if len(data2) >= expected_len:
                                        break
                            
                            msg_type2, _, resp_attrs2 = parse_attrs(data2)
                            
                            result['success'] = msg_type2 == STUN_ALLOCATE_SUCCESS_RESPONSE
                            if not result['realm']:
                                result['realm'] = self._extract_realm(resp_attrs2)
                            if not result['banner']:
                                result['banner'] = self._extract_banner(resp_attrs2)
                            
                            if msg_type2 == STUN_ALLOCATE_ERROR_RESPONSE:
                                error_code2 = resp_attrs2.get(STUN_ATTR_ERROR_CODE)
                                if error_code2:
                                    error_class2 = error_code2[2]
                                    error_number2 = error_code2[3]
                                    # 如果是400错误，尝试短期凭据
                                    if error_class2 == 4 and error_number2 == 0:
                                        integrity_key_short = opaque_string(password)
                                        attrs_short = [
                                            stun_attr(STUN_ATTR_USERNAME, username.encode()),
                                            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00")),
                                        ]
                                        tid_short = gen_tid()
                                        req_short = build_msg_with_short_term_credential(STUN_ALLOCATE_REQUEST, tid_short, attrs_short, integrity_key_short, add_fingerprint=True)
                                        sock.sendall(req_short)
                                        
                                        data_short = b''
                                        while len(data_short) < 20:
                                            chunk = sock.recv(2000)
                                            if not chunk:
                                                break
                                            data_short += chunk
                                            if len(data_short) >= 20:
                                                msg_len = struct.unpack("!H", data_short[2:4])[0]
                                                expected_len = 20 + msg_len
                                                if len(data_short) >= expected_len:
                                                    break
                                        
                                        msg_type_short, _, resp_attrs_short = parse_attrs(data_short)
                                        result['success'] = msg_type_short == STUN_ALLOCATE_SUCCESS_RESPONSE
                                        if not result['realm']:
                                            result['realm'] = self._extract_realm(resp_attrs_short)
                                        if not result['banner']:
                                            result['banner'] = self._extract_banner(resp_attrs_short)
                                        result['error'] = self._extract_error_message(resp_attrs_short) if msg_type_short == STUN_ALLOCATE_ERROR_RESPONSE else None
                                    else:
                                        result['error'] = self._extract_error_message(resp_attrs2)
                                else:
                                    result['error'] = self._extract_error_message(resp_attrs2)
                            else:
                                result['error'] = None
                        else:
                            result['error'] = self._extract_error_message(resp_attrs1)
                    else:
                        result['error'] = self._extract_error_message(resp_attrs1)
                else:
                    result['error'] = self._extract_error_message(resp_attrs1)
            elif msg_type1 == STUN_ALLOCATE_SUCCESS_RESPONSE:
                result['success'] = True
                result['error'] = None
            else:
                result['error'] = f"Unexpected response type: 0x{msg_type1:04x}"
            
            sock.close()
            return result
            
        except socket.timeout:
            return None
        except Exception as e:
            result['error'] = str(e)
            return result
    
    def _query_rdns(self, ip: str) -> Optional[str]:
        """查询反向DNS"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return None
    
    def _query_whois(self, ip: str) -> Optional[Dict]:
        """查询WHOIS信息"""
        try:
            import subprocess
            result = subprocess.run(
                ['whois', ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return {
                    'raw': result.stdout[:1000]  # 限制长度
                }
        except:
            pass
        return None
    
    def scan_ip(self, ip: str) -> Dict:
        """扫描单个IP地址"""
        # 移除每个IP的扫描输出，减少输出频率
        # print(f"[*] 扫描 {ip}...", flush=True)
        
        result = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'udp_3478': None,
            'tcp_3478': None,
            'tcp_443': None,
            'tcp_5349': None,
            'rdns': None,
            'whois': None
        }
        
        # 测试UDP 3478
        result['udp_3478'] = self._test_udp_turn(ip, 3478)
        
        # 测试TCP 3478（先TLS，失败再纯TCP）
        result['tcp_3478'] = self._test_tcp_turn(ip, 3478, use_tls=True)
        
        # 测试TCP 443（先TLS，失败再纯TCP）
        result['tcp_443'] = self._test_tcp_turn(ip, 443, use_tls=True)
        
        # 测试TCP 5349（先TLS，失败再纯TCP）
        result['tcp_5349'] = self._test_tcp_turn(ip, 5349, use_tls=True)
        
        # 检查是否有任何TURN响应（成功或错误响应都算，但不包括连接错误）
        has_turn_response = False
        for test_result in [result['udp_3478'], result['tcp_3478'], result['tcp_443'], result['tcp_5349']]:
            if self._is_turn_response(test_result):
                has_turn_response = True
                break
        
        # 如果发现TURN服务器，查询rDNS和whois
        if has_turn_response:
            print(f"[+] 发现TURN服务器: {ip}", flush=True)
            result['rdns'] = self._query_rdns(ip)
            result['whois'] = self._query_whois(ip)
        
        return result
    
    def _is_stun_error(self, error: Optional[str]) -> bool:
        """判断error是否是STUN协议错误（而非连接错误）"""
        if not error:
            return False
        # STUN错误码格式通常是 "4XX Reason" 或 "XXX Reason"
        # 连接错误通常是 "[Errno XXX] ..." 或包含 "Connection", "timeout", "refused" 等
        error_lower = error.lower()
        connection_errors = ['connection refused', 'connection reset', 'connection aborted', 
                            'timeout', 'errno', 'network is unreachable', 'no route to host',
                            'name or service not known', 'nodename nor servname provided']
        if any(conn_err in error_lower for conn_err in connection_errors):
            return False
        # 如果error看起来像STUN错误码（如 "401 Unauthorized", "400 Bad Request"）
        # 或者包含常见的STUN错误原因
        if error.startswith(('4', '3', '5', '6')) and len(error) > 3:
            # 可能是STUN错误码
            return True
        return False
    
    def _is_turn_response(self, result: Optional[Dict]) -> bool:
        """判断是否为TURN响应（成功或错误响应都算）"""
        if not result:
            return False
        # 如果有realm或banner，肯定是TURN响应
        if result.get('realm') or result.get('banner'):
            return True
        # 如果success为True，肯定是TURN响应
        if result.get('success') is True:
            return True
        # 如果error是STUN协议错误（而非连接错误），也算TURN响应
        error = result.get('error')
        if error and self._is_stun_error(error):
            return True
        # 其他情况（连接错误等）不算TURN响应
        return False
    
    def scan_all_ips(self):
        """扫描所有IPv4地址空间"""
        import sys
        sys.stdout.flush()  # 强制刷新输出缓冲区
        
        print("[+] 开始扫描所有IPv4地址空间...", flush=True)
        print(f"[+] 使用 {self.threads} 个线程", flush=True)
        
        # 获取最后扫描的IP地址
        last_scanned_ip = self._get_last_scanned_ip()
        start_ip_int = 0
        if last_scanned_ip:
            start_ip_int = self._ip_to_int(last_scanned_ip) + 1
            print(f"[+] 从上次中断处继续: {last_scanned_ip} -> {self._int_to_ip(start_ip_int)}", flush=True)
        else:
            print("[+] 从头开始扫描", flush=True)
        
        # 计算总数和跳过的数量
        total_ips = 256 * 256 * 256 * 256
        skipped_count = 0
        if start_ip_int > 0:
            skipped_count = start_ip_int
        
        print(f"[+] 总共需要扫描 {total_ips} 个IP地址", flush=True)
        if skipped_count > 0:
            print(f"[+] 跳过已扫描的 {skipped_count} 个IP地址", flush=True)
            print(f"[+] 剩余 {total_ips - skipped_count} 个IP地址待扫描", flush=True)
        
        # 创建任务队列（限制队列大小，避免内存占用过大）
        task_queue = queue.Queue(maxsize=100000)  # 最多缓存10万个任务
        producer_done = threading.Event()  # 生产者完成标志
        
        # IP地址生成器
        def ip_generator():
            """生成IP地址的生成器"""
            for a in range(256):
                for b in range(256):
                    for c in range(256):
                        for d in range(256):
                            ip = f"{a}.{b}.{c}.{d}"
                            ip_int = self._ip_to_int(ip)
                            if ip_int >= start_ip_int:
                                yield ip
        
        # 生产者线程：将IP地址放入队列
        def producer():
            """生产者线程，将IP地址放入队列"""
            count = 0
            try:
                for ip in ip_generator():
                    # 如果IP已经扫描过，跳过
                    if ip in self.results and ip != '_metadata':
                        continue
                    task_queue.put(ip)
                    count += 1
                    # 每生成10万个IP输出一次进度
                    if count % 100000 == 0:
                        print(f"[*] 已生成 {count} 个任务到队列...", flush=True)
                print(f"[+] IP地址生成完成，共 {count} 个任务", flush=True)
            finally:
                producer_done.set()  # 标记生产者完成
        
        # 启动生产者线程
        producer_thread = threading.Thread(target=producer, daemon=True)
        producer_thread.start()
        
        # 工作线程
        def worker():
            while True:
                try:
                    ip = task_queue.get(timeout=1)
                    self.scan_count += 1
                    
                    # 如果IP已经扫描过（且不是元数据字段），跳过
                    if ip in self.results and ip != '_metadata':
                        task_queue.task_done()
                        continue
                    
                    # 扫描IP
                    result = self.scan_ip(ip)
                    
                    # 更新最后扫描的IP地址（实时更新，线程安全）
                    self._update_last_scanned_ip(ip)
                    
                    # 如果发现TURN服务器，保存结果
                    if self._is_turn_response(result.get('udp_3478')) or \
                       self._is_turn_response(result.get('tcp_3478')) or \
                       self._is_turn_response(result.get('tcp_443')) or \
                       self._is_turn_response(result.get('tcp_5349')):
                        with self.lock:
                            self.results[ip] = result
                            self.found_count += 1
                            self._save_results()
                            print(f"[+] 已发现 {self.found_count} 个TURN服务器", flush=True)
                    
                    # 每扫描1000个IP打印一次进度
                    if self.scan_count % 1000 == 0:
                        remaining = total_ips - skipped_count - self.scan_count
                        print(f"[*] 进度: {self.scan_count}/{total_ips - skipped_count} (已扫描: {self.scan_count + skipped_count}/{total_ips}, {100*(self.scan_count + skipped_count)/total_ips:.2f}%), 已发现: {self.found_count}, 剩余: {remaining}", flush=True)
                    
                    task_queue.task_done()
                except queue.Empty:
                    # 如果队列为空且生产者已完成，则退出
                    if producer_done.is_set() and task_queue.empty():
                        break
                    # 否则继续等待
                    continue
                except Exception as e:
                    print(f"[-] 线程错误: {e}", flush=True)
                    task_queue.task_done()
        
        # 启动线程
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        # 等待生产者线程完成
        producer_thread.join()
        
        # 等待所有任务完成
        task_queue.join()
        
        # 等待所有线程完成
        for t in threads:
            t.join()
        
        print("\n" + "="*70, flush=True)
        print("📊 扫描完成", flush=True)
        print("="*70, flush=True)
        print(f"总共扫描: {self.scan_count} 个IP地址", flush=True)
        print(f"发现TURN服务器: {self.found_count} 个", flush=True)
        print(f"结果已保存到: {self.output_file}", flush=True)
    
    def scan_ips_from_csv(self, csv_file: str):
        """从CSV文件读取IP列表并多线程扫描"""
        print(f"[+] 从CSV文件读取IP列表: {csv_file}", flush=True)
        
        # 读取CSV文件，提取IP列（第二列，索引1）
        # 使用列表保持顺序，同时用set来去重检查
        ip_list = []
        ip_seen = set()
        total_rows = 0
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader)  # 跳过表头
                for row in reader:
                    total_rows += 1
                    if len(row) > 1:
                        ip = row[1].strip()  # IP列是第二列（索引1）
                        if ip and ip not in ip_seen:  # 去重但保持顺序
                            ip_list.append(ip)
                            ip_seen.add(ip)
                    # 每读取10万行输出一次进度
                    if total_rows % 100000 == 0:
                        print(f"[*] 已读取 {total_rows:,} 行，提取到 {len(ip_list):,} 个唯一IP...", flush=True)
        except Exception as e:
            print(f"[-] 读取CSV文件失败: {e}", flush=True)
            return
        
        total_ips = len(ip_list)
        print(f"[+] 从CSV文件读取完成: 共 {total_rows:,} 行，提取到 {total_ips:,} 个唯一IP地址", flush=True)
        
        # 获取最后扫描的IP地址，并在列表中查找
        last_scanned_ip = self._get_last_scanned_ip()
        start_index = 0
        if last_scanned_ip:
            try:
                start_index = ip_list.index(last_scanned_ip) + 1
                print(f"[+] 从上次中断处继续: {last_scanned_ip} (索引 {ip_list.index(last_scanned_ip)}) -> 从索引 {start_index} 开始", flush=True)
            except ValueError:
                # last_scanned_ip不在列表中，从头开始
                print(f"[!] 警告: last_scanned_ip ({last_scanned_ip}) 不在CSV列表中，从头开始扫描", flush=True)
                start_index = 0
        
        # 只处理start_index之后的IP
        ip_list_to_scan = ip_list[start_index:]
        skipped_count = start_index
        remaining_count = len(ip_list_to_scan)
        
        print(f"[+] 跳过已扫描的 {skipped_count} 个IP地址", flush=True)
        print(f"[+] 剩余 {remaining_count} 个IP地址待扫描", flush=True)
        print(f"[+] 使用 {self.threads} 个线程", flush=True)
        
        # 创建任务队列
        task_queue = queue.Queue()
        for ip in ip_list_to_scan:
            task_queue.put(ip)
        
        # 工作线程
        def worker():
            while True:
                try:
                    ip = task_queue.get(timeout=1)
                    self.scan_count += 1
                    
                    # 如果IP已经扫描过（且不是元数据字段），跳过
                    if ip in self.results and ip != '_metadata':
                        task_queue.task_done()
                        continue
                    
                    # 扫描IP
                    result = self.scan_ip(ip)
                    
                    # 更新最后扫描的IP地址（实时更新，线程安全）
                    self._update_last_scanned_ip(ip)
                    
                    # 如果发现TURN服务器，保存结果
                    if self._is_turn_response(result.get('udp_3478')) or \
                       self._is_turn_response(result.get('tcp_3478')) or \
                       self._is_turn_response(result.get('tcp_443')) or \
                       self._is_turn_response(result.get('tcp_5349')):
                        with self.lock:
                            self.results[ip] = result
                            self.found_count += 1
                            self._save_results()
                            print(f"[+] 已发现 {self.found_count} 个TURN服务器: {ip}", flush=True)
                    
                    # 每扫描100个IP打印一次进度
                    if self.scan_count % 100 == 0:
                        remaining = remaining_count - self.scan_count
                        print(f"[*] 进度: {self.scan_count}/{remaining_count} ({100*self.scan_count/remaining_count:.2f}%), 已发现: {self.found_count}, 剩余: {remaining}", flush=True)
                    
                    task_queue.task_done()
                except queue.Empty:
                    break
                except Exception as e:
                    print(f"[-] 线程错误: {e}", flush=True)
                    task_queue.task_done()
        
        # 启动线程
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        # 等待所有任务完成
        task_queue.join()
        
        # 等待所有线程完成
        for t in threads:
            t.join()
        
        print("\n" + "="*70, flush=True)
        print("📊 扫描完成", flush=True)
        print("="*70, flush=True)
        print(f"总共扫描: {self.scan_count} 个IP地址", flush=True)
        print(f"发现TURN服务器: {self.found_count} 个", flush=True)
        print(f"结果已保存到: {self.output_file}", flush=True)

def make_json_serializable(obj):
    """递归地将对象转换为JSON可序列化的格式"""
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    elif isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [make_json_serializable(item) for item in obj]
    else:
        # 对于其他类型（如IPv4Address, IPv6Address等），转换为字符串
        return str(obj)

def main():
    parser = argparse.ArgumentParser(description='TURN服务器IP地址空间扫描工具')
    parser.add_argument('--ip', help='测试单个IP地址')
    parser.add_argument('--scan-all', action='store_true', help='扫描所有IPv4地址空间')
    parser.add_argument('--csv', help='从CSV文件读取IP列表并多线程扫描')
    parser.add_argument('--output', default='turn_scan_results.json', help='输出文件路径')
    parser.add_argument('--threads', type=int, default=10, help='线程数（默认10）')
    
    args = parser.parse_args()
    
    if not args.ip and not args.scan_all and not args.csv:
        parser.print_help()
        return
    
    scanner = TURNIPScanner(output_file=args.output, threads=args.threads)
    
    if args.ip:
        # 单IP测试模式
        result = scanner.scan_ip(args.ip)
        # 确保结果可序列化
        result = make_json_serializable(result)
        print("\n" + "="*70)
        print("📊 扫描结果")
        print("="*70)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
        # 保存结果
        scanner.results[args.ip] = result
        scanner._save_results()
    elif args.csv:
        # CSV文件模式
        scanner.scan_ips_from_csv(args.csv)
    else:
        # 全IPv4扫描模式
        scanner.scan_all_ips()

if __name__ == "__main__":
    main()