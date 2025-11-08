"""
TURN客户端实现 - 支持UDP和TCP传输协议

本实现基于以下RFC规范：
- RFC 5766: TURN (Traversal Using Relays around NAT)
- RFC 6062: TURN Extensions for TCP Allocations

功能特性：
1. UDP TURN: 通过UDP通道发送数据
2. TCP TURN: 通过TCP连接发送数据（RFC 6062扩展）

使用方法：
- python turn_client.py          # 运行UDP演示
- python turn_client.py udp     # 运行UDP演示
- python turn_client.py tcp      # 运行基本TCP演示
- python turn_client.py tcp-full # 运行完整TCP演示（包含数据连接）
"""

import socket
import struct
import hmac
import hashlib
import random
import os
import sys
import zlib
import dns.resolver
import dns.exception
import time
import unicodedata

# === 配置 ===
# 从配置文件导入TURN服务器配置
# 添加父目录到路径，以便导入config模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT, USERNAME, PASSWORD, REALM,
    DEFAULT_TIMEOUT, DEFAULT_CHANNEL_NUMBER
)

# STUN/TURN 常量
STUN_BINDING_REQUEST  = 0x0001
STUN_ALLOCATE_REQUEST = 0x0003
STUN_CREATE_PERMISSION_REQUEST = 0x0008
STUN_CHANNEL_BIND_REQUEST = 0x0009
# TCP TURN 扩展方法 (RFC 6062)
STUN_CONNECT_REQUEST = 0x000a
STUN_CONNECTION_BIND_REQUEST = 0x000b
STUN_CONNECTION_ATTEMPT_INDICATION = 0x000c
STUN_MAGIC_COOKIE     = 0x2112A442

# STUN 响应类型
STUN_ALLOCATE_SUCCESS_RESPONSE = 0x0103
STUN_ALLOCATE_ERROR_RESPONSE = 0x0113
STUN_CREATE_PERMISSION_SUCCESS_RESPONSE = 0x0108
STUN_CREATE_PERMISSION_ERROR_RESPONSE = 0x0118
STUN_CHANNEL_BIND_SUCCESS_RESPONSE = 0x0109
STUN_CHANNEL_BIND_ERROR_RESPONSE = 0x0119

# STUN 属性类型
STUN_ATTR_USERNAME = 0x0006
STUN_ATTR_MESSAGE_INTEGRITY = 0x0008
STUN_ATTR_MESSAGE_INTEGRITY_SHA256 = 0x001c
STUN_ATTR_REALM = 0x0014
STUN_ATTR_NONCE = 0x0015
STUN_ATTR_REQUESTED_TRANSPORT = 0x0019
STUN_ATTR_PASSWORD_ALGORITHMS = 0x8002
STUN_ATTR_PASSWORD_ALGORITHM = 0x8001
STUN_ATTR_USERHASH = 0x001f
STUN_ATTR_XOR_PEER_ADDRESS = 0x0012
STUN_ATTR_CHANNEL_NUMBER = 0x000C
STUN_ATTR_FINGERPRINT = 0x8028
STUN_ATTR_ERROR_CODE = 0x0009
STUN_ATTR_ALTERNATE_SERVER = 0x8023
# TCP TURN 扩展属性 (RFC 6062)
STUN_ATTR_CONNECTION_ID = 0x002a

def gen_tid():
    return os.urandom(12)

def is_ip_address(hostname):
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

def discover_turn_server_ips(hostname, max_queries=20):
    """发现TURN服务器的所有IP地址"""
    print(f"[+] Discovering all IPs for {hostname}")
    
    # 如果是IP地址，直接返回
    if is_ip_address(hostname):
        print(f"[+] Input is IP address: {hostname}")
        return [hostname]
    
    dns_servers = [
        '8.8.8.8', '8.8.4.4',      # Google DNS
        '1.1.1.1', '1.0.0.1',      # Cloudflare DNS
        '208.67.222.222', '208.67.220.220',  # OpenDNS
    ]
    
    discovered_ips = set()
    
    # 1. 系统DNS解析
    try:
        ip = socket.gethostbyname(hostname)
        discovered_ips.add(ip)
        print(f"[+] System DNS: {hostname} -> {ip}")
    except socket.gaierror as e:
        print(f"[-] System DNS failed: {e}")
    
    # 2. 多DNS服务器解析
    for i in range(max_queries):
        dns_server = random.choice(dns_servers)
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            answers = resolver.resolve(hostname, 'A')
            for answer in answers:
                ip = str(answer)
                if ip not in discovered_ips:
                    discovered_ips.add(ip)
                    print(f"[+] DNS query via {dns_server}: {hostname} -> {ip}")
            time.sleep(0.1)  # 避免DNS限制
        except dns.exception.DNSException:
            continue
    
    ip_list = list(discovered_ips)
    print(f"[+] Total discovered {len(ip_list)} IPs: {ip_list}")
    return ip_list

def resolve_server_address(server_host, server_port):
    """解析服务器地址，支持域名和IP地址"""
    try:
        # 尝试解析域名
        ip_address = socket.gethostbyname(server_host)
        print(f"[+] Resolved {server_host} to {ip_address}")
        return (ip_address, server_port)
    except socket.gaierror as e:
        print(f"[-] Failed to resolve {server_host}: {e}")
        return None

def resolve_peer_address(peer_host):
    """解析对等方地址，支持域名和IP地址"""
    try:
        # 尝试解析域名
        ip_address = socket.gethostbyname(peer_host)
        print(f"[+] Resolved peer {peer_host} to {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"[-] Failed to resolve peer {peer_host}: {e}")
        return None

def parse_alternate_server(attr_data):
    """解析ALTERNATE-SERVER属性"""
    if len(attr_data) < 8:
        return None
    
    # ALTERNATE-SERVER属性格式与MAPPED-ADDRESS相同（RFC8489第14.15节）
    # 格式: reserved(1) + family(1) + port(2) + address(4 for IPv4, 16 for IPv6)
    # 注意：不是XOR编码的，直接使用网络字节序
    
    # 尝试解析为未编码的地址
    if len(attr_data) == 8:  # IPv4
        # 第0字节是保留字段，必须为0
        reserved = attr_data[0]
        if reserved != 0:
            return None
            
        # 第1字节是地址族
        family = attr_data[1]
        if family == 1:  # IPv4
            # 端口是网络字节序，直接解析
            port = struct.unpack("!H", attr_data[2:4])[0]
            
            # IP地址是网络字节序，直接解析
            address = socket.inet_ntoa(attr_data[4:8])
            
            return (address, port)
    elif len(attr_data) == 20:  # IPv6
        # 第0字节是保留字段，必须为0
        reserved = attr_data[0]
        if reserved != 0:
            return None
            
        # 第1字节是地址族
        family = attr_data[1]
        if family == 2:  # IPv6
            # 端口是网络字节序，直接解析
            port = struct.unpack("!H", attr_data[2:4])[0]
            
            # IPv6地址是网络字节序，直接解析
            address = socket.inet_ntop(socket.AF_INET6, attr_data[4:20])
            
            return (address, port)
    
    return None

def stun_attr(attr_type, value):
    pad_len = (4 - (len(value) % 4)) % 4
    return struct.pack("!HH", attr_type, len(value)) + value + b"\x00" * pad_len

def opaque_string(s):
    """处理 OpaqueString profile (RFC 8265)
    
    根据 RFC 8265，OpaqueString profile 用于处理密码：
    1. 确保字符串只包含 FreeformClass 允许的 Unicode 代码点
    2. 非 ASCII 空格映射到 SPACE (U+0020)
    3. 应用 Unicode Normalization Form C (NFC)
    4. 不允许控制字符（除了 SPACE）
    
    Args:
        s: 输入字符串或字节
        
    Returns:
        UTF-8 编码的字节串，符合 OpaqueString profile
    """
    if isinstance(s, bytes):
        # 如果已经是字节，去除尾随 null 字节
        s = s.rstrip(b'\x00')
        # 尝试解码为字符串，然后重新编码
        try:
            s = s.decode('utf-8')
        except UnicodeDecodeError:
            # 如果无法解码，直接使用原始字节（去除尾随 null 后）
            return s
    else:
        # 如果是字符串，去除尾随 null 字符
        s = s.rstrip('\x00')
    
    # 空字符串检查
    if not s:
        raise ValueError("OpaqueString cannot be zero-length")
    
    # 1. 非 ASCII 空格映射到 SPACE (U+0020)
    # 查找所有 Unicode 类别为 "Zs"（空格分隔符）但不是 U+0020 的字符
    normalized = []
    for char in s:
        if unicodedata.category(char) == 'Zs' and ord(char) != 0x0020:
            normalized.append(' ')  # 映射到 SPACE (U+0020)
        else:
            normalized.append(char)
    s = ''.join(normalized)
    
    # 2. 检查控制字符（不允许控制字符，除了 SPACE）
    # 控制字符的 Unicode 类别是 "Cc"（除了 SPACE 本身就是控制字符）
    # 但 SPACE (U+0020) 是允许的
    # 实际上，根据 RFC 8265，只允许 SPACE (U+0020)，不允许其他控制字符
    filtered = []
    for char in s:
        if ord(char) == 0x0020:  # SPACE 是允许的
            filtered.append(char)
        elif unicodedata.category(char).startswith('C'):  # 控制字符类别
            # 不允许控制字符（除了 SPACE）
            raise ValueError(f"Control character U+{ord(char):04X} is not allowed in OpaqueString")
        else:
            filtered.append(char)
    s = ''.join(filtered)
    
    # 3. 应用 Unicode Normalization Form C (NFC)
    s = unicodedata.normalize('NFC', s)
    
    # 4. 使用 UTF-8 编码
    return s.encode('utf-8')

def compute_long_term_hmac_key(username, realm, password):
    """计算长期凭据的 HMAC Key (RFC 8489 Section 9.2.2)
    
    key = MD5(username ":" OpaqueString(realm) ":" OpaqueString(password))
    
    Args:
        username: 用户名（字符串）
        realm: REALM（字节串）
        password: 密码（字符串）
        
    Returns:
        16字节的HMAC key
    """
    # 处理 realm：如果是字节串，先解码
    if isinstance(realm, bytes):
        realm_str = realm.decode('utf-8', errors='ignore')
    else:
        realm_str = str(realm)
    
    # 使用 OpaqueString 处理 realm 和 password
    if realm_str == '':
        realm_opaque = ''
    else:
        realm_opaque = opaque_string(realm_str).decode('utf-8')
    password_opaque = opaque_string(password).decode('utf-8')
    
    # 拼接：username:realm:password
    key_str = f"{username}:{realm_opaque}:{password_opaque}"
    
    # 计算 MD5
    return hashlib.md5(key_str.encode('utf-8')).digest()

def check_nonce_cookie(nonce):
    """检查 nonce 是否以 nonce cookie 开头 (RFC 8489 Section 9.2)
    
    nonce cookie = "obMatJos2" + base64(24-bit STUN Security Features)
    
    Args:
        nonce: NONCE 属性值（字节串）
        
    Returns:
        (has_cookie, security_features_bits) 或 (False, None)
    """
    if not nonce or len(nonce) < 13:
        return False, None
    
    cookie_prefix = b"obMatJos2"
    if not nonce.startswith(cookie_prefix):
        return False, None
    
    # 提取 Security Features（3字节，base64编码）
    if len(nonce) < 13:
        return False, None
    
    try:
        # 提取 base64 编码的 Security Features（4个字符）
        import base64
        features_b64 = nonce[9:13].decode('ascii')
        features_bytes = base64.b64decode(features_b64 + '==')  # 添加填充以确保正确解码
        if len(features_bytes) >= 3:
            # 提取前3个字节（24位）
            features = features_bytes[:3]
            return True, features
    except:
        pass
    
    return True, None  # 有 cookie 但无法解析 features

def parse_password_algorithms(attr_value):
    """解析 PASSWORD-ALGORITHMS 属性 (RFC 8489 Section 14.11)
    
    Args:
        attr_value: PASSWORD-ALGORITHMS 属性值（字节串）
        
    Returns:
        算法列表，每个元素是 (algorithm_id, parameters)
    """
    algorithms = []
    if len(attr_value) < 2:
        return algorithms
    
    # PASSWORD-ALGORITHMS 格式：每个算法占2字节（算法ID）
    # 但实际上每个算法可能包含参数，格式更复杂
    # 简化实现：假设每个算法2字节
    i = 0
    while i + 2 <= len(attr_value):
        alg_id = struct.unpack("!H", attr_value[i:i+2])[0]
        algorithms.append(alg_id)
        i += 2
    
    return algorithms

def verify_short_term_response_integrity(data, integrity_key, expected_algorithm=None):
    """验证短期凭据响应的消息完整性 (RFC 8489 Section 9.1.4)
    
    Args:
        data: 原始响应数据（字节串）
        integrity_key: HMAC密钥（OpaqueString(password)）
        expected_algorithm: 期望的算法 ('sha256', 'sha1', 'both', None)
        
    Returns:
        (is_valid, algorithm_used) 或 (False, None)
    """
    try:
        msg_type, tid, attrs = parse_attrs(data)
        
        # 检查响应中是否包含消息完整性属性
        has_sha256 = STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in attrs
        has_sha1 = STUN_ATTR_MESSAGE_INTEGRITY in attrs
        
        # 根据 RFC 8489 Section 9.1.4，如果客户端只发送了一个算法，响应必须匹配
        if expected_algorithm == 'sha256':
            if not has_sha256:
                print("[!] Response does not contain MESSAGE-INTEGRITY-SHA256 as expected")
                return False, None
        elif expected_algorithm == 'sha1':
            if not has_sha1:
                print("[!] Response does not contain MESSAGE-INTEGRITY as expected")
                return False, None
        
        # 如果两者都不存在，返回 False
        if not has_sha256 and not has_sha1:
            return False, None
        
        # 验证消息完整性
        if has_sha256:
            # 验证 MESSAGE-INTEGRITY-SHA256 (RFC 8489 Section 14.6)
            # 找到 MESSAGE-INTEGRITY-SHA256 属性的位置
            pos = 20  # 跳过 header
            msg_len = struct.unpack("!H", data[2:4])[0]
            mi_sha256_pos = None
            mi_sha256_value = None
            mi_sha256_len = None
            
            # 解析消息找到 MESSAGE-INTEGRITY-SHA256 属性
            current_pos = 20
            while current_pos < 20 + msg_len:
                atype, alen = struct.unpack("!HH", data[current_pos:current_pos+4])
                if atype == STUN_ATTR_MESSAGE_INTEGRITY_SHA256:
                    mi_sha256_pos = current_pos
                    mi_sha256_len = alen
                    mi_sha256_value = data[current_pos+4:current_pos+4+alen]
                    break
                current_pos += 4 + ((alen + 3) // 4) * 4
            
            if mi_sha256_pos is None:
                return False, None
            
            # 构建用于 HMAC 计算的消息（到 MESSAGE-INTEGRITY-SHA256 之前）
            # Header length 字段指向 MESSAGE-INTEGRITY-SHA256 的末尾
            # 但 HMAC 计算只包含到 MESSAGE-INTEGRITY-SHA256 之前的属性
            body_before_mi = data[20:mi_sha256_pos]
            
            # 重新构建 header，length 指向 MESSAGE-INTEGRITY-SHA256 的末尾（不包括 FINGERPRINT）
            # 根据 RFC 8489 Section 14.6，length 字段必须调整为指向 MESSAGE-INTEGRITY-SHA256 的末尾
            length_for_hmac = mi_sha256_pos + 4 + mi_sha256_len - 20
            
            # 重新构建 header
            header = struct.pack("!HHI12s", msg_type, length_for_hmac, struct.unpack("!I", data[4:8])[0], tid)
            
            # 计算 HMAC-SHA256
            msg_for_hmac = header + body_before_mi
            computed_hmac = hmac.new(integrity_key, msg_for_hmac, hashlib.sha256).digest()
            
            # 比较（响应中的值可能被截断到至少16字节）
            if len(mi_sha256_value) >= 16:
                if computed_hmac[:len(mi_sha256_value)] == mi_sha256_value:
                    return True, 'sha256'
                else:
                    print("[!] MESSAGE-INTEGRITY-SHA256 verification failed")
                    return False, None
            else:
                return False, None
                
        elif has_sha1:
            # 验证 MESSAGE-INTEGRITY (RFC 8489 Section 14.5)
            # 找到 MESSAGE-INTEGRITY 属性的位置
            pos = 20
            msg_len = struct.unpack("!H", data[2:4])[0]
            mi_pos = None
            mi_value = None
            mi_len = None
            
            current_pos = 20
            while current_pos < 20 + msg_len:
                atype, alen = struct.unpack("!HH", data[current_pos:current_pos+4])
                if atype == STUN_ATTR_MESSAGE_INTEGRITY:
                    mi_pos = current_pos
                    mi_len = alen
                    mi_value = data[current_pos+4:current_pos+4+alen]
                    break
                current_pos += 4 + ((alen + 3) // 4) * 4
            
            if mi_pos is None:
                return False, None
            
            # 构建用于 HMAC 计算的消息
            # 根据 RFC 8489 Section 14.5，如果存在 MESSAGE-INTEGRITY-SHA256，HMAC 计算包含它
            if has_sha256:
                # 找到 MESSAGE-INTEGRITY-SHA256 的位置
                mi_sha256_pos = None
                mi_sha256_len = None
                current_pos = 20
                while current_pos < 20 + msg_len:
                    atype, alen = struct.unpack("!HH", data[current_pos:current_pos+4])
                    if atype == STUN_ATTR_MESSAGE_INTEGRITY_SHA256:
                        mi_sha256_pos = current_pos
                        mi_sha256_len = alen
                        break
                    current_pos += 4 + ((alen + 3) // 4) * 4
                
                if mi_sha256_pos and mi_sha256_pos < mi_pos:
                    # MESSAGE-INTEGRITY-SHA256 在 MESSAGE-INTEGRITY 之前
                    # HMAC 计算包含到 MESSAGE-INTEGRITY-SHA256 的末尾（包括 MESSAGE-INTEGRITY-SHA256）
                    body_before_mi = data[20:mi_sha256_pos + 4 + mi_sha256_len]
                    # Length 指向 MESSAGE-INTEGRITY 的末尾
                    length_for_hmac = mi_pos + 4 + mi_len - 20
                else:
                    body_before_mi = data[20:mi_pos]
                    length_for_hmac = mi_pos + 4 + mi_len - 20
            else:
                body_before_mi = data[20:mi_pos]
                length_for_hmac = mi_pos + 4 + mi_len - 20
            
            # 根据 RFC 8489 Section 14.5，length 字段必须调整为指向 MESSAGE-INTEGRITY 的末尾
            # FINGERPRINT 在 MESSAGE-INTEGRITY 之后，不影响 HMAC 计算
            
            # 重新构建 header
            header = struct.pack("!HHI12s", msg_type, length_for_hmac, struct.unpack("!I", data[4:8])[0], tid)
            
            # 计算 HMAC-SHA1
            msg_for_hmac = header + body_before_mi
            computed_hmac = hmac.new(integrity_key, msg_for_hmac, hashlib.sha1).digest()
            
            # 比较
            if computed_hmac == mi_value:
                return True, 'sha1'
            else:
                print("[!] MESSAGE-INTEGRITY verification failed")
                return False, None
        
        return False, None
            
    except Exception as e:
        print(f"[!] Error verifying response integrity: {e}")
        import traceback
        traceback.print_exc()
        return False, None

def build_msg(msg_type, tid, attrs, integrity_key=None, add_fingerprint=False):
    
    body = b"".join(attrs)
    
    if integrity_key:
        # 创建占位符HMAC
        mi_dummy = b"\x00" * 20
        mi_attr = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY, len(mi_dummy)) + mi_dummy
        body_with_mac_mi = body + mi_attr
        
        # 如果使用FINGERPRINT，先创建占位符FINGERPRINT
        fp_attr = None
        if add_fingerprint:
            fp_attr_mi = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, 0)  # 占位符FINGERPRINT
            body_with_mac_mi_and_fp_mi = body_with_mac_mi + fp_attr_mi
        
        # 生成header，长度包含FINGERPRINT（如果使用）
        header = struct.pack("!HHI12s", msg_type, len(body_with_mac_mi), STUN_MAGIC_COOKIE, tid)
        msg_for_hmac = header + body
        
        # 计算HMAC-SHA1
        hmac_val = hmac.new(integrity_key, msg_for_hmac, hashlib.sha1).digest()
        
        # 替换占位符为真实HMAC
        hmac_attr = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY, len(hmac_val)) + hmac_val
        body_with_hmac = body + hmac_attr
        header = struct.pack("!HHI12s", msg_type, len(body_with_hmac), STUN_MAGIC_COOKIE, tid)
        msg = header + body_with_hmac

        # 如果使用FINGERPRINT，重新添加占位符
        if add_fingerprint:
            body_with_hmac_and_fp_attr_mi = body_with_hmac + fp_attr_mi
        
            # 重新生成header，包含fingerprint dummy
            header = struct.pack("!HHI12s", msg_type, len(body_with_hmac_and_fp_attr_mi), STUN_MAGIC_COOKIE, tid)
            
        
        
            # 基于当前消息计算CRC32
            msg_for_crc = header + body_with_hmac # 但是 msg_for_crc 不包含FINGERPRINT
            crc32_val = zlib.crc32(msg_for_crc) & 0xffffffff
            #print(crc32_val.to_bytes(4).hex())
            fingerprint_val = crc32_val ^ 0x5354554e
            #print(fingerprint_val.to_bytes(4).hex())
            # 替换占位符FINGERPRINT为真实值
            fp_attr = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, fingerprint_val)
            
            # 重新构建消息
            body_with_hmac_and_fp = body + hmac_attr + fp_attr
            header = struct.pack("!HHI12s", msg_type, len(body_with_hmac_and_fp), STUN_MAGIC_COOKIE, tid)
            msg = header + body_with_hmac_and_fp
    else:
        msg = struct.pack("!HHI12s", msg_type, len(body), STUN_MAGIC_COOKIE, tid) + body

    return msg


def build_msg_with_short_term_credential(msg_type, tid, attrs, integrity_key, add_fingerprint=False):
    """构建包含短期凭证认证的STUN消息（RFC 8489）
    
    根据 RFC 8489 第 9.1.2 节，短期凭证必须同时包含：
    1. USERNAME
    2. MESSAGE-INTEGRITY-SHA256
    3. MESSAGE-INTEGRITY
    
    属性顺序：USERNAME -> MESSAGE-INTEGRITY-SHA256 -> MESSAGE-INTEGRITY -> FINGERPRINT
    
    Args:
        msg_type: 消息类型
        tid: 事务ID
        attrs: 属性列表（不包含认证相关属性）
        integrity_key: HMAC密钥（OpaqueString(password)）
        add_fingerprint: 是否添加FINGERPRINT属性
    
    Returns:
        构建好的STUN消息（字节串）
    """
    body = b"".join(attrs)
    
    # 创建占位符
    mi_sha256_dummy = b"\x00" * 32  # MESSAGE-INTEGRITY-SHA256 占位符（32字节）
    mi_dummy = b"\x00" * 20  # MESSAGE-INTEGRITY 占位符（20字节）
    
    # 构建带占位符的消息体
    mi_sha256_attr_dummy = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY_SHA256, len(mi_sha256_dummy)) + mi_sha256_dummy
    mi_attr_dummy = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY, len(mi_dummy)) + mi_dummy
    
    body_with_mi_sha256_dummy = body + mi_sha256_attr_dummy
    body_with_both_mi_dummy = body_with_mi_sha256_dummy + mi_attr_dummy
    
    # 如果使用FINGERPRINT，添加占位符
    fp_attr_dummy = None
    if add_fingerprint:
        fp_attr_dummy = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, 0)
        body_with_all_dummy = body_with_both_mi_dummy + fp_attr_dummy
    else:
        body_with_all_dummy = body_with_both_mi_dummy
    
    # 计算 MESSAGE-INTEGRITY-SHA256
    # 输入：header + body（到 MESSAGE-INTEGRITY-SHA256 之前的属性）
    # Length 字段指向 MESSAGE-INTEGRITY-SHA256 的末尾（如果使用FINGERPRINT，长度也应包含FINGERPRINT dummy）
    if add_fingerprint:
        body_with_mi_sha256_dummy_and_fp_dummy = body_with_mi_sha256_dummy + fp_attr_dummy
        header_for_sha256 = struct.pack("!HHI12s", msg_type, len(body_with_mi_sha256_dummy_and_fp_dummy), STUN_MAGIC_COOKIE, tid)
    else:
        header_for_sha256 = struct.pack("!HHI12s", msg_type, len(body_with_mi_sha256_dummy), STUN_MAGIC_COOKIE, tid)
    msg_for_sha256 = header_for_sha256 + body  # HMAC计算时不包含FINGERPRINT dummy
    
    # 计算 HMAC-SHA256
    hmac_sha256_val = hmac.new(integrity_key, msg_for_sha256, hashlib.sha256).digest()
    
    # 替换 MESSAGE-INTEGRITY-SHA256 占位符
    mi_sha256_attr = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY_SHA256, len(hmac_sha256_val)) + hmac_sha256_val
    body_with_mi_sha256 = body + mi_sha256_attr
    
    # 计算 MESSAGE-INTEGRITY
    # 输入：header + body（到 MESSAGE-INTEGRITY 之前的属性，即包含 MESSAGE-INTEGRITY-SHA256）
    # Length 字段指向 MESSAGE-INTEGRITY 的末尾（如果使用FINGERPRINT，长度也应包含FINGERPRINT dummy）
    body_with_mi_sha256_and_mi_dummy = body_with_mi_sha256 + mi_attr_dummy
    if add_fingerprint:
        body_with_mi_sha256_and_mi_dummy_and_fp_dummy = body_with_mi_sha256_and_mi_dummy + fp_attr_dummy
        header_for_sha1 = struct.pack("!HHI12s", msg_type, len(body_with_mi_sha256_and_mi_dummy_and_fp_dummy), STUN_MAGIC_COOKIE, tid)
    else:
        header_for_sha1 = struct.pack("!HHI12s", msg_type, len(body_with_mi_sha256_and_mi_dummy), STUN_MAGIC_COOKIE, tid)
    msg_for_sha1 = header_for_sha1 + body_with_mi_sha256  # HMAC计算时不包含FINGERPRINT dummy
    
    # 计算 HMAC-SHA1
    hmac_sha1_val = hmac.new(integrity_key, msg_for_sha1, hashlib.sha1).digest()
    
    # 替换 MESSAGE-INTEGRITY 占位符
    mi_attr = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY, len(hmac_sha1_val)) + hmac_sha1_val
    body_with_both_mi = body_with_mi_sha256 + mi_attr
    
    # 如果使用FINGERPRINT，计算并添加
    if add_fingerprint:
        body_with_both_mi_and_fp_dummy = body_with_both_mi + fp_attr_dummy
        header_for_fp = struct.pack("!HHI12s", msg_type, len(body_with_both_mi_and_fp_dummy), STUN_MAGIC_COOKIE, tid)
        
        # 计算CRC32（不包含FINGERPRINT）
        msg_for_crc = header_for_fp + body_with_both_mi
        crc32_val = zlib.crc32(msg_for_crc) & 0xffffffff
        fingerprint_val = crc32_val ^ 0x5354554e
        
        # 替换FINGERPRINT占位符
        fp_attr = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, fingerprint_val)
        body_with_all = body_with_both_mi + fp_attr
        header = struct.pack("!HHI12s", msg_type, len(body_with_all), STUN_MAGIC_COOKIE, tid)
        msg = header + body_with_all
    else:
        header = struct.pack("!HHI12s", msg_type, len(body_with_both_mi), STUN_MAGIC_COOKIE, tid)
        msg = header + body_with_both_mi
    
    return msg


def build_msg_with_short_term_credential_sha256_only(msg_type, tid, attrs, integrity_key, add_fingerprint=False):
    """构建包含短期凭证认证的STUN消息（仅使用MESSAGE-INTEGRITY-SHA256）
    
    属性顺序：USERNAME -> MESSAGE-INTEGRITY-SHA256 -> FINGERPRINT
    
    Args:
        msg_type: 消息类型
        tid: 事务ID
        attrs: 属性列表（不包含认证相关属性）
        integrity_key: HMAC密钥（OpaqueString(password)）
        add_fingerprint: 是否添加FINGERPRINT属性
    
    Returns:
        构建好的STUN消息（字节串）
    """
    body = b"".join(attrs)
    
    # 创建占位符
    mi_sha256_dummy = b"\x00" * 32  # MESSAGE-INTEGRITY-SHA256 占位符（32字节）
    
    # 构建带占位符的消息体
    mi_sha256_attr_dummy = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY_SHA256, len(mi_sha256_dummy)) + mi_sha256_dummy
    body_with_mi_sha256_dummy = body + mi_sha256_attr_dummy
    
    # 如果使用FINGERPRINT，添加占位符
    fp_attr_dummy = None
    if add_fingerprint:
        fp_attr_dummy = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, 0)
        body_with_mi_sha256_dummy_and_fp_dummy = body_with_mi_sha256_dummy + fp_attr_dummy
        header_for_sha256 = struct.pack("!HHI12s", msg_type, len(body_with_mi_sha256_dummy_and_fp_dummy), STUN_MAGIC_COOKIE, tid)
    else:
        header_for_sha256 = struct.pack("!HHI12s", msg_type, len(body_with_mi_sha256_dummy), STUN_MAGIC_COOKIE, tid)
    msg_for_sha256 = header_for_sha256 + body  # HMAC计算时不包含FINGERPRINT dummy
    
    # 计算 HMAC-SHA256
    hmac_sha256_val = hmac.new(integrity_key, msg_for_sha256, hashlib.sha256).digest()
    
    # 替换 MESSAGE-INTEGRITY-SHA256 占位符
    mi_sha256_attr = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY_SHA256, len(hmac_sha256_val)) + hmac_sha256_val
    body_with_mi_sha256 = body + mi_sha256_attr
    
    # 如果使用FINGERPRINT，计算并添加
    if add_fingerprint:
        body_with_mi_sha256_and_fp_dummy = body_with_mi_sha256 + fp_attr_dummy
        header_for_fp = struct.pack("!HHI12s", msg_type, len(body_with_mi_sha256_and_fp_dummy), STUN_MAGIC_COOKIE, tid)
        
        # 计算CRC32（不包含FINGERPRINT）
        msg_for_crc = header_for_fp + body_with_mi_sha256
        crc32_val = zlib.crc32(msg_for_crc) & 0xffffffff
        fingerprint_val = crc32_val ^ 0x5354554e
        
        # 替换FINGERPRINT占位符
        fp_attr = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, fingerprint_val)
        body_with_all = body_with_mi_sha256 + fp_attr
        header = struct.pack("!HHI12s", msg_type, len(body_with_all), STUN_MAGIC_COOKIE, tid)
        msg = header + body_with_all
    else:
        header = struct.pack("!HHI12s", msg_type, len(body_with_mi_sha256), STUN_MAGIC_COOKIE, tid)
        msg = header + body_with_mi_sha256
    
    return msg


def build_msg_with_short_term_credential_sha1_only(msg_type, tid, attrs, integrity_key, add_fingerprint=False):
    """构建包含短期凭证认证的STUN消息（仅使用MESSAGE-INTEGRITY）
    
    属性顺序：USERNAME -> MESSAGE-INTEGRITY -> FINGERPRINT
    
    Args:
        msg_type: 消息类型
        tid: 事务ID
        attrs: 属性列表（不包含认证相关属性）
        integrity_key: HMAC密钥（OpaqueString(password)）
        add_fingerprint: 是否添加FINGERPRINT属性
    
    Returns:
        构建好的STUN消息（字节串）
    """
    body = b"".join(attrs)
    
    # 创建占位符
    mi_dummy = b"\x00" * 20  # MESSAGE-INTEGRITY 占位符（20字节）
    
    # 构建带占位符的消息体
    mi_attr_dummy = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY, len(mi_dummy)) + mi_dummy
    body_with_mi_dummy = body + mi_attr_dummy
    
    # 如果使用FINGERPRINT，添加占位符
    fp_attr_dummy = None
    if add_fingerprint:
        fp_attr_dummy = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, 0)
        body_with_mi_dummy_and_fp_dummy = body_with_mi_dummy + fp_attr_dummy
        header_for_sha1 = struct.pack("!HHI12s", msg_type, len(body_with_mi_dummy_and_fp_dummy), STUN_MAGIC_COOKIE, tid)
    else:
        header_for_sha1 = struct.pack("!HHI12s", msg_type, len(body_with_mi_dummy), STUN_MAGIC_COOKIE, tid)
    msg_for_sha1 = header_for_sha1 + body  # HMAC计算时不包含FINGERPRINT dummy
    
    # 计算 HMAC-SHA1
    hmac_sha1_val = hmac.new(integrity_key, msg_for_sha1, hashlib.sha1).digest()
    
    # 替换 MESSAGE-INTEGRITY 占位符
    mi_attr = struct.pack("!HH", STUN_ATTR_MESSAGE_INTEGRITY, len(hmac_sha1_val)) + hmac_sha1_val
    body_with_mi = body + mi_attr
    
    # 如果使用FINGERPRINT，计算并添加
    if add_fingerprint:
        body_with_mi_and_fp_dummy = body_with_mi + fp_attr_dummy
        header_for_fp = struct.pack("!HHI12s", msg_type, len(body_with_mi_and_fp_dummy), STUN_MAGIC_COOKIE, tid)
        
        # 计算CRC32（不包含FINGERPRINT）
        msg_for_crc = header_for_fp + body_with_mi
        crc32_val = zlib.crc32(msg_for_crc) & 0xffffffff
        fingerprint_val = crc32_val ^ 0x5354554e
        
        # 替换FINGERPRINT占位符
        fp_attr = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, fingerprint_val)
        body_with_all = body_with_mi + fp_attr
        header = struct.pack("!HHI12s", msg_type, len(body_with_all), STUN_MAGIC_COOKIE, tid)
        msg = header + body_with_all
    else:
        header = struct.pack("!HHI12s", msg_type, len(body_with_mi), STUN_MAGIC_COOKIE, tid)
        msg = header + body_with_mi
    
    return msg


def parse_attrs(data):
    attrs = {}
    msg_type, msg_len, magic, tid = struct.unpack("!HHI12s", data[:20])
    pos = 20
    while pos < 20 + msg_len:
        atype, alen = struct.unpack("!HH", data[pos:pos+4])
        aval = data[pos+4:pos+4+alen]
        attrs[atype] = aval
        pos += 4 + ((alen + 3) // 4) * 4
    return msg_type, tid, attrs

def allocate_single_server(server_address, username=None, password=None, realm=None, use_short_term_credential=False):
    """向单个服务器分配UDP TURN中继地址
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    # 使用传入的认证信息或默认值
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    try:
        if use_short_term_credential:
            # 短期凭证：直接发送带认证的请求，不需要nonce/realm
            # 短期凭证的HMAC密钥直接使用password（OpaqueString profile）
            integrity_key = opaque_string(auth_password)
            print(f"[+] Using short-term credential mechanism")
            print(f"[+] HMAC key (password): {auth_password}")
            print(f"[+] HMAC key (bytes): {integrity_key.hex()}")
            
            attrs = [
                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT
            ]
            
            # 根据 RFC 8489 Section 9.1.2，默认情况下必须同时包含 MESSAGE-INTEGRITY-SHA256 和 MESSAGE-INTEGRITY
            tid = gen_tid()
            req = build_msg_with_short_term_credential(STUN_ALLOCATE_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
            sock.sendto(req, server_address)
            
            try:
                data, _ = sock.recvfrom(2000)
                msg_type, tid, resp_attrs = parse_attrs(data)
                print("[+] Allocate response attrs:", resp_attrs)
            except socket.timeout:
                print("[-] Timeout waiting for response")
                sock.close()
                return None
            
            # 检查响应状态
            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                print("[+] UDP TURN allocation successful")
                
                # 检测服务器在响应中使用的算法类型（用于后续请求，RFC 8489 Section 9.1.5）
                has_sha256 = STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in resp_attrs
                has_sha1 = STUN_ATTR_MESSAGE_INTEGRITY in resp_attrs
                
                if has_sha256:
                    mi_algorithm = 'sha256'
                    print(f"[+] Server uses MESSAGE-INTEGRITY-SHA256, subsequent requests will use SHA256 only (RFC 8489 Section 9.1.5)")
                elif has_sha1:
                    mi_algorithm = 'sha1'
                    print(f"[+] Server uses MESSAGE-INTEGRITY, subsequent requests will use SHA1 only (RFC 8489 Section 9.1.5)")
                else:
                    mi_algorithm = 'both'  # 默认
                    print(f"[!] Warning: No MI attribute in response, using method: {mi_algorithm}")
                
                # 根据 RFC 8489 Section 9.1.4，验证响应中的消息完整性
                is_valid, verified_algorithm = verify_short_term_response_integrity(data, integrity_key, expected_algorithm='both')
                if not is_valid:
                    print("[!] Response integrity verification failed per RFC 8489 Section 9.1.4")
                    # 根据 RFC 8489 Section 9.1.4，对于不可靠传输，丢弃响应
                    print("[!] Discarding response (unreliable transport)")
                    sock.close()
                    return None
                
                if verified_algorithm and verified_algorithm != mi_algorithm:
                    # 如果验证函数返回的算法与检测到的不一致，使用验证函数返回的
                    mi_algorithm = verified_algorithm
                
                nonce = None
                server_realm = None
                attrs = resp_attrs
            elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = resp_attrs.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    error_reason = error_code[4:].decode('utf-8', errors='ignore')
                    print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                print("[-] UDP TURN allocation failed")
                sock.close()
                return None
            else:
                print(f"[-] Unexpected response type: 0x{msg_type:04x}")
                sock.close()
                return None
        else:
            # 长期凭证：按照 RFC 8489 Section 9.2
            # 1. 第一次 Allocate 请求（无认证，RFC 8489 Section 9.2.3.1）
            print("[+] Using long-term credential mechanism")
            print("[+] Step 1: Sending first request without authentication (RFC 8489 Section 9.2.3.1)")
            tid1 = gen_tid()
            req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))  # REQUESTED-TRANSPORT (UDP=17)
            ])
            sock.sendto(req1, server_address)
            data, _ = sock.recvfrom(2000)
            msg_type, tid, attrs = parse_attrs(data)
            print("[+] First response attrs:", attrs)

            # 检查响应：应该是 401 并包含 REALM 和 NONCE (RFC 8489 Section 9.2.4)
            if msg_type != STUN_ALLOCATE_ERROR_RESPONSE:
                print("[-] Expected 401 error response for first request")
                sock.close()
                return None
            
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                if error_class != 4 or error_number != 1:
                    print(f"[-] Expected 401 error, got {error_class}{error_number:02d}")
                    sock.close()
                    return None

            # 提取 nonce 和 realm
            nonce = attrs.get(STUN_ATTR_NONCE)   # NONCE
            server_realm = attrs.get(STUN_ATTR_REALM)   # REALM
            password_algorithms = attrs.get(STUN_ATTR_PASSWORD_ALGORITHMS)  # PASSWORD-ALGORITHMS (可选)
            
            if nonce is None or server_realm is None:
                print("[-] No nonce/realm in 401 response, exiting")
                sock.close()
                return None

            print(f"[+] Got nonce={nonce}, realm={server_realm}")
            
            # 检查 nonce cookie (RFC 8489 Section 9.2)
            has_cookie, security_features = check_nonce_cookie(nonce)
            if has_cookie:
                print("[+] Nonce has cookie prefix (RFC 8489 compliant)")
                if security_features:
                    print(f"[+] Security features: {security_features.hex()}")
            
            # 处理 PASSWORD-ALGORITHMS（如果存在）
            selected_password_algorithm = None
            if password_algorithms:
                algorithms = parse_password_algorithms(password_algorithms)
                print(f"[+] Server supports password algorithms: {algorithms}")
                # 选择第一个支持的算法（通常是 MD5=0x0001，SHA-256=0x0002）
                if algorithms:
                    selected_password_algorithm = algorithms[0]
                    print(f"[+] Selected password algorithm: 0x{selected_password_algorithm:04x}")

            # 2. 第二次 Allocate 请求（RFC 8489 Section 9.2.3.2）
            print("[+] Step 2: Sending authenticated request")
            tid2 = gen_tid()
            
            # 计算 HMAC Key（使用 OpaqueString 处理 realm 和 password）
            integrity_key = compute_long_term_hmac_key(auth_username, server_realm, auth_password)
            print(f"[+] Computed HMAC key (MD5): {integrity_key.hex()}")

            attrs2 = [
                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
                stun_attr(STUN_ATTR_REALM, server_realm),              # REALM
                stun_attr(STUN_ATTR_NONCE, nonce),              # NONCE
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT
            ]
            
            # 如果服务器提供了 PASSWORD-ALGORITHMS，必须在请求中包含
            if password_algorithms:
                attrs2.append(stun_attr(STUN_ATTR_PASSWORD_ALGORITHMS, password_algorithms))
                if selected_password_algorithm:
                    attrs2.append(stun_attr(STUN_ATTR_PASSWORD_ALGORITHM, struct.pack("!H", selected_password_algorithm)))

            req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
            sock.sendto(req2, server_address)

            data, _ = sock.recvfrom(2000)
            msg_type, tid, attrs = parse_attrs(data)
            print("[+] Final response attrs:", attrs)
            
            # 检测服务器使用的消息完整性算法
            mi_algorithm = None
            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                if STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in attrs:
                    mi_algorithm = 'sha256'
                    print("[+] Server uses MESSAGE-INTEGRITY-SHA256")
                elif STUN_ATTR_MESSAGE_INTEGRITY in attrs:
                    mi_algorithm = 'sha1'
                    print("[+] Server uses MESSAGE-INTEGRITY (SHA1)")
            
            # 处理 438 (Stale Nonce) 错误
            if msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = attrs.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    if error_class == 4 and error_number == 38:  # 438 Stale Nonce
                        print("[+] Received 438 Stale Nonce, retrying with new nonce")
                        new_nonce = attrs.get(STUN_ATTR_NONCE)
                        new_realm = attrs.get(STUN_ATTR_REALM)
                        new_password_algorithms = attrs.get(STUN_ATTR_PASSWORD_ALGORITHMS)
                        
                        if new_nonce and new_realm:
                            nonce = new_nonce
                            server_realm = new_realm
                            if new_password_algorithms:
                                password_algorithms = new_password_algorithms
                                algorithms = parse_password_algorithms(password_algorithms)
                                if algorithms:
                                    selected_password_algorithm = algorithms[0]
                            
                            # 使用新的 nonce 重试
                            tid3 = gen_tid()
                            integrity_key = compute_long_term_hmac_key(auth_username, server_realm, auth_password)
                            attrs3 = [
                                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
                                stun_attr(STUN_ATTR_REALM, server_realm),
                                stun_attr(STUN_ATTR_NONCE, nonce),
                                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),
                            ]
                            if password_algorithms:
                                attrs3.append(stun_attr(STUN_ATTR_PASSWORD_ALGORITHMS, password_algorithms))
                                if selected_password_algorithm:
                                    attrs3.append(stun_attr(STUN_ATTR_PASSWORD_ALGORITHM, struct.pack("!H", selected_password_algorithm)))
                            
                            req3 = build_msg(STUN_ALLOCATE_REQUEST, tid3, attrs3, integrity_key, add_fingerprint=True)
                            sock.sendto(req3, server_address)
                            data, _ = sock.recvfrom(2000)
                            msg_type, tid, attrs = parse_attrs(data)
                            print("[+] Retry response attrs:", attrs)
                            
                            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                                if STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in attrs:
                                    mi_algorithm = 'sha256'
                                elif STUN_ATTR_MESSAGE_INTEGRITY in attrs:
                                    mi_algorithm = 'sha1'
        
        # 检查响应状态
        if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
            print("[+] UDP TURN allocation successful")
            return sock, nonce, server_realm, integrity_key, server_address, mi_algorithm
        elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            print("[-] UDP TURN allocation failed: Error response")
            # 检查错误码
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)  # ERROR-CODE attribute
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                error_reason = error_code[4:].decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                
                # 处理300 (Try Alternate)错误
                if error_class == 3 and error_number == 0:  # 300 Try Alternate
                    print("[+] Received Try Alternate error, checking for alternate server...")
                    alternate_server = attrs.get(STUN_ATTR_ALTERNATE_SERVER)
                    if alternate_server:
                        print(f"[+] Found ALTERNATE-SERVER attribute: {alternate_server.hex()}")
                        alt_addr = parse_alternate_server(alternate_server)
                        if alt_addr:
                            print(f"[+] Found alternate server: {alt_addr[0]}:{alt_addr[1]}")
                            sock.close()
                            # 递归调用使用备用服务器（注意：返回值包含 mi_algorithm）
                            return allocate_single_server(alt_addr, username, password, realm, use_short_term_credential)
                        else:
                            print(f"[-] Failed to parse alternate server address: {alternate_server.hex()}")
                    else:
                        print("[+] No alternate server provided")
                        sock.close()
                        return None
            sock.close()
            return None
        else:
            print(f"[-] Unexpected response type: 0x{msg_type:04x}")
            sock.close()
            return None
            
    except Exception as e:
        print(f"[-] Allocation failed: {e}")
        sock.close()
        return None

def allocate_single_server_with_alternate(server_address, username=None, password=None, realm=None, tried_alternate_servers=None, use_short_term_credential=False):
    """向单个服务器分配UDP TURN中继地址，支持ALTERNATE-SERVER重试
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        tried_alternate_servers: 已尝试的备用服务器集合
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    if tried_alternate_servers is None:
        tried_alternate_servers = set()
    
    # 使用传入的认证信息或默认值
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    try:
        if use_short_term_credential:
            # 短期凭证：直接发送带认证的请求，不需要nonce/realm
            # 短期凭证的HMAC密钥直接使用password（OpaqueString profile）
            integrity_key = opaque_string(auth_password)
            print(f"[+] Using short-term credential mechanism")
            print(f"[+] HMAC key (password): {auth_password}")
            print(f"[+] HMAC key (bytes): {integrity_key.hex()}")
            
            attrs = [
                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT
            ]
            
            # 尝试不同的认证方法：先尝试同时包含两个MESSAGE-INTEGRITY，如果400则回退
            build_methods = [
                ("both", build_msg_with_short_term_credential),  # 同时包含 SHA256 和 SHA1
                ("sha256_only", build_msg_with_short_term_credential_sha256_only),  # 仅 SHA256
                ("sha1_only", build_msg_with_short_term_credential_sha1_only),  # 仅 SHA1
            ]
            
            msg_type = None
            tid = None
            resp_attrs = None
            mi_algorithm = None  # 服务器使用的算法类型
            
            for method_name, build_func in build_methods:
                tid = gen_tid()
                print(f"[+] Trying authentication method: {method_name}")
                req = build_func(STUN_ALLOCATE_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
                sock.sendto(req, server_address)
                
                try:
                    data, _ = sock.recvfrom(2000)
                    msg_type, tid, resp_attrs = parse_attrs(data)
                    print("[+] Allocate response attrs:", resp_attrs)
                    
                    # 检查响应状态
                    if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                        print(f"[+] UDP TURN allocation successful with method: {method_name}")
                        # 检测服务器在响应中使用的算法类型（用于后续请求）
                        if STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in resp_attrs:
                            mi_algorithm = 'sha256'
                            print(f"[+] Server uses MESSAGE-INTEGRITY-SHA256, subsequent requests will use SHA256 only")
                        elif STUN_ATTR_MESSAGE_INTEGRITY in resp_attrs:
                            mi_algorithm = 'sha1'
                            print(f"[+] Server uses MESSAGE-INTEGRITY, subsequent requests will use SHA1 only")
                        else:
                            # 如果响应中没有找到，使用当前成功的方法
                            if method_name == 'sha256_only':
                                mi_algorithm = 'sha256'
                            elif method_name == 'sha1_only':
                                mi_algorithm = 'sha1'
                            else:
                                mi_algorithm = 'both'  # 默认
                            print(f"[+] Warning: No MI attribute in response, using method: {mi_algorithm}")
                        break  # 成功，退出循环
                    elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                        error_code = resp_attrs.get(STUN_ATTR_ERROR_CODE)
                        if error_code:
                            error_class = error_code[2]
                            error_number = error_code[3]
                            error_reason = error_code[4:].decode('utf-8', errors='ignore')
                            print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                            
                            # 如果是400错误且还有备选方法，继续尝试
                            if error_class == 4 and error_number == 0 and build_methods.index((method_name, build_func)) < len(build_methods) - 1:
                                print(f"[+] Got 400 error, trying next method...")
                                continue
                            else:
                                # 不是400错误，或者已经是最后一个方法，退出循环
                                break
                        else:
                            break
                    else:
                        print(f"[-] Unexpected response type: 0x{msg_type:04x}")
                        break
                except socket.timeout:
                    print(f"[-] Timeout with method: {method_name}")
                    if build_methods.index((method_name, build_func)) < len(build_methods) - 1:
                        print(f"[+] Trying next method...")
                        continue
                    else:
                        break
            
            # 短期凭证不需要nonce和realm，返回None作为占位符
            nonce = None
            server_realm = None
            # 如果所有方法都失败，resp_attrs 可能为 None
            if resp_attrs is None:
                attrs = {}
            else:
                attrs = resp_attrs
        else:
            # 长期凭证：按照 RFC 8489 Section 9.2
            # 1. 第一次 Allocate 请求（无认证，RFC 8489 Section 9.2.3.1）
            print("[+] Using long-term credential mechanism")
            print("[+] Step 1: Sending first request without authentication (RFC 8489 Section 9.2.3.1)")
            tid1 = gen_tid()
            req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00"))  # REQUESTED-TRANSPORT (UDP=17)
            ])
            sock.sendto(req1, server_address)
            data, _ = sock.recvfrom(2000)
            msg_type, tid, attrs = parse_attrs(data)
            print("[+] First response attrs:", attrs)

            # 检查响应：应该是 401 并包含 REALM 和 NONCE (RFC 8489 Section 9.2.4)
            if msg_type != STUN_ALLOCATE_ERROR_RESPONSE:
                print("[-] Expected 401 error response for first request")
                sock.close()
                return None
            
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                if error_class != 4 or error_number != 1:
                    print(f"[-] Expected 401 error, got {error_class}{error_number:02d}")
                    sock.close()
                    return None

            # 提取 nonce 和 realm
            nonce = attrs.get(STUN_ATTR_NONCE)   # NONCE
            server_realm = attrs.get(STUN_ATTR_REALM)   # REALM
            password_algorithms = attrs.get(STUN_ATTR_PASSWORD_ALGORITHMS)  # PASSWORD-ALGORITHMS (可选)
            
            if nonce is None or server_realm is None:
                print("[-] No nonce/realm in 401 response, exiting")
                sock.close()
                return None

            print(f"[+] Got nonce={nonce}, realm={server_realm}")
            
            # 检查 nonce cookie (RFC 8489 Section 9.2)
            has_cookie, security_features = check_nonce_cookie(nonce)
            if has_cookie:
                print("[+] Nonce has cookie prefix (RFC 8489 compliant)")
                if security_features:
                    print(f"[+] Security features: {security_features.hex()}")
            
            # 处理 PASSWORD-ALGORITHMS（如果存在）
            selected_password_algorithm = None
            if password_algorithms:
                algorithms = parse_password_algorithms(password_algorithms)
                print(f"[+] Server supports password algorithms: {algorithms}")
                # 选择第一个支持的算法（通常是 MD5=0x0001，SHA-256=0x0002）
                if algorithms:
                    selected_password_algorithm = algorithms[0]
                    print(f"[+] Selected password algorithm: 0x{selected_password_algorithm:04x}")

            # 2. 第二次 Allocate 请求（RFC 8489 Section 9.2.3.2）
            print("[+] Step 2: Sending authenticated request")
            tid2 = gen_tid()
            
            # 计算 HMAC Key（使用 OpaqueString 处理 realm 和 password）
            integrity_key = compute_long_term_hmac_key(auth_username, server_realm, auth_password)
            print(f"[+] Computed HMAC key (MD5): {integrity_key.hex()}")

            attrs2 = [
                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
                stun_attr(STUN_ATTR_REALM, server_realm),              # REALM
                stun_attr(STUN_ATTR_NONCE, nonce),              # NONCE
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT
            ]
            
            # 如果服务器提供了 PASSWORD-ALGORITHMS，必须在请求中包含
            if password_algorithms:
                attrs2.append(stun_attr(STUN_ATTR_PASSWORD_ALGORITHMS, password_algorithms))
                if selected_password_algorithm:
                    attrs2.append(stun_attr(STUN_ATTR_PASSWORD_ALGORITHM, struct.pack("!H", selected_password_algorithm)))

            req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
            sock.sendto(req2, server_address)

            data, _ = sock.recvfrom(2000)
            msg_type, tid, attrs = parse_attrs(data)
            print("[+] Final response attrs:", attrs)
            
            # 检测服务器使用的消息完整性算法
            mi_algorithm = None
            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                if STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in attrs:
                    mi_algorithm = 'sha256'
                    print("[+] Server uses MESSAGE-INTEGRITY-SHA256")
                elif STUN_ATTR_MESSAGE_INTEGRITY in attrs:
                    mi_algorithm = 'sha1'
                    print("[+] Server uses MESSAGE-INTEGRITY (SHA1)")
            
            # 处理 438 (Stale Nonce) 错误
            if msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = attrs.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    if error_class == 4 and error_number == 38:  # 438 Stale Nonce
                        print("[+] Received 438 Stale Nonce, retrying with new nonce")
                        new_nonce = attrs.get(STUN_ATTR_NONCE)
                        new_realm = attrs.get(STUN_ATTR_REALM)
                        new_password_algorithms = attrs.get(STUN_ATTR_PASSWORD_ALGORITHMS)
                        
                        if new_nonce and new_realm:
                            nonce = new_nonce
                            server_realm = new_realm
                            if new_password_algorithms:
                                password_algorithms = new_password_algorithms
                                algorithms = parse_password_algorithms(password_algorithms)
                                if algorithms:
                                    selected_password_algorithm = algorithms[0]
                            
                            # 使用新的 nonce 重试
                            tid3 = gen_tid()
                            integrity_key = compute_long_term_hmac_key(auth_username, server_realm, auth_password)
                            attrs3 = [
                                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
                                stun_attr(STUN_ATTR_REALM, server_realm),
                                stun_attr(STUN_ATTR_NONCE, nonce),
                                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),
                            ]
                            if password_algorithms:
                                attrs3.append(stun_attr(STUN_ATTR_PASSWORD_ALGORITHMS, password_algorithms))
                                if selected_password_algorithm:
                                    attrs3.append(stun_attr(STUN_ATTR_PASSWORD_ALGORITHM, struct.pack("!H", selected_password_algorithm)))
                            
                            req3 = build_msg(STUN_ALLOCATE_REQUEST, tid3, attrs3, integrity_key, add_fingerprint=True)
                            sock.sendto(req3, server_address)
                            data, _ = sock.recvfrom(2000)
                            msg_type, tid, attrs = parse_attrs(data)
                            print("[+] Retry response attrs:", attrs)
                            
                            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                                if STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in attrs:
                                    mi_algorithm = 'sha256'
                                elif STUN_ATTR_MESSAGE_INTEGRITY in attrs:
                                    mi_algorithm = 'sha1'
        
        # 检查响应状态
        if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
            print("[+] UDP TURN allocation successful")
            # 对于长期凭证，mi_algorithm 为 None，后续请求使用默认的 build_msg
            if not use_short_term_credential:
                mi_algorithm = None
            return sock, nonce, server_realm, integrity_key, server_address, mi_algorithm
        elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            print("[-] UDP TURN allocation failed: Error response")
            # 检查错误码
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)  # ERROR-CODE attribute
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                error_reason = error_code[4:].decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                
                # 处理300 (Try Alternate)错误
                if error_class == 3 and error_number == 0:  # 300 Try Alternate
                    print("[+] Received Try Alternate error, checking for alternate server...")
                    alternate_server = attrs.get(STUN_ATTR_ALTERNATE_SERVER)
                    if alternate_server:
                        print(f"[+] Found ALTERNATE-SERVER attribute: {alternate_server.hex()}")
                        alt_addr = parse_alternate_server(alternate_server)
                        if alt_addr:
                            alt_server_str = f"{alt_addr[0]}:{alt_addr[1]}"
                            print(f"[+] Found alternate server: {alt_server_str}")
                            
                            # 检查是否已经尝试过这个ALTERNATE-SERVER
                            if alt_server_str in tried_alternate_servers:
                                print(f"[+] ALTERNATE-SERVER {alt_server_str} already tried, skipping to avoid loop")
                                sock.close()
                                return None
                            
                            # 添加到已尝试列表
                            tried_alternate_servers.add(alt_server_str)
                            
                            sock.close()
                            print(f"[+] Recursively trying ALTERNATE-SERVER {alt_server_str}")
                            # 递归调用使用备用服务器
                            return allocate_single_server_with_alternate(alt_addr, username, password, realm, tried_alternate_servers, use_short_term_credential)
                        else:
                            print(f"[-] Failed to parse alternate server address: {alternate_server.hex()}")
                    else:
                        print("[+] No alternate server provided")
                        sock.close()
                        return None
            sock.close()
            return None
        else:
            print(f"[-] Unexpected response type: 0x{msg_type:04x}")
            sock.close()
            return None
            
    except Exception as e:
        print(f"[-] Allocation failed: {e}")
        sock.close()
        return None

def allocate(server_address=None, username=None, password=None, realm=None, server_hostname=None, use_short_term_credential=False):
    """分配UDP TURN中继地址，支持多IP备选和自动重试
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        server_hostname: 服务器主机名（用于DNS发现）
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    # 获取服务器主机名用于DNS发现
    if server_hostname is None:
        server_hostname = server_address[0]
    
    # 发现所有IP地址
    server_ips = discover_turn_server_ips(server_hostname)
    server_port = server_address[1]
    
    print(f"[+] Trying {len(server_ips)} IP addresses for TURN server")
    
    # 用于跟踪已尝试的ALTERNATE-SERVER地址，避免无限循环
    tried_alternate_servers = set()
    
    # 尝试每个IP地址
    for i, ip in enumerate(server_ips):
        current_address = (ip, server_port)
        print(f"[+] Attempt {i+1}/{len(server_ips)}: Trying {current_address}")
        
        result = allocate_single_server_with_alternate(current_address, username, password, realm, tried_alternate_servers, use_short_term_credential)
        if result:
            # result现在包含实际连接的服务器地址
            actual_connected_address = result[4] if len(result) > 4 else current_address
            print(f"[+] Successfully allocated on {actual_connected_address}")
            return result
        else:
            print(f"[-] Failed to allocate on {current_address}")
    
    print("[-] All UDP IP addresses failed")
    return None


def allocate_tcp_single_server(server_address, username=None, password=None, realm=None, use_tls=False, use_short_term_credential=False):
    """向单个服务器分配TCP TURN中继地址（使用TCP传输）
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        use_tls: 是否使用TLS
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    # 使用传入的认证信息或默认值
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
        
    # TCP TURN需要先建立TCP控制连接
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_sock.settimeout(10)
    
    try:
        # 连接到TURN服务器
        control_sock.connect(server_address)
        print(f"[+] Connected to TURN server {server_address}")
        
        # 如果使用TLS，建立SSL连接
        if use_tls:
            import ssl
            print("[+] Establishing TLS connection...")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            control_sock = context.wrap_socket(control_sock, server_hostname=server_address[0])
            print("[+] TLS connection established")
        
        if use_short_term_credential:
            # 短期凭证：直接发送带认证的请求，不需要nonce/realm
            # 短期凭证的HMAC密钥直接使用password（OpaqueString profile）
            integrity_key = opaque_string(auth_password)
            print(f"[+] Using short-term credential mechanism")
            print(f"[+] HMAC key (password): {auth_password}")
            print(f"[+] HMAC key (bytes): {integrity_key.hex()}")
            
            attrs = [
                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT (TCP=6)
            ]
            
            # 根据 RFC 8489 Section 9.1.2，默认情况下必须同时包含 MESSAGE-INTEGRITY-SHA256 和 MESSAGE-INTEGRITY
            tid = gen_tid()
            req = build_msg_with_short_term_credential(STUN_ALLOCATE_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
            control_sock.send(req)
            
            try:
                data = control_sock.recv(2000)
                msg_type, tid, resp_attrs = parse_attrs(data)
                print("[+] Allocate response attrs:", resp_attrs)
            except socket.timeout:
                print("[-] Timeout waiting for response")
                control_sock.close()
                return None
            
            # 检查响应状态
            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                print("[+] TCP TURN allocation successful")
                
                # 检测服务器在响应中使用的算法类型（用于后续请求，RFC 8489 Section 9.1.5）
                has_sha256 = STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in resp_attrs
                has_sha1 = STUN_ATTR_MESSAGE_INTEGRITY in resp_attrs
                
                if has_sha256:
                    mi_algorithm = 'sha256'
                    print(f"[+] Server uses MESSAGE-INTEGRITY-SHA256, subsequent requests will use SHA256 only (RFC 8489 Section 9.1.5)")
                elif has_sha1:
                    mi_algorithm = 'sha1'
                    print(f"[+] Server uses MESSAGE-INTEGRITY, subsequent requests will use SHA1 only (RFC 8489 Section 9.1.5)")
                else:
                    mi_algorithm = 'both'  # 默认
                    print(f"[!] Warning: No MI attribute in response, using method: {mi_algorithm}")
                
                # 根据 RFC 8489 Section 9.1.4，验证响应中的消息完整性
                is_valid, verified_algorithm = verify_short_term_response_integrity(data, integrity_key, expected_algorithm='both')
                if not is_valid:
                    print("[!] Response integrity verification failed per RFC 8489 Section 9.1.4")
                    # 根据 RFC 8489 Section 9.1.4，对于可靠传输，立即结束事务并报告完整性保护违规
                    print("[!] Ending transaction (reliable transport) - integrity protection violated")
                    control_sock.close()
                    return None
                
                if verified_algorithm and verified_algorithm != mi_algorithm:
                    mi_algorithm = verified_algorithm
                
                nonce = None
                server_realm = None
                attrs = resp_attrs
            elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = resp_attrs.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    error_reason = error_code[4:].decode('utf-8', errors='ignore')
                    print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                print("[-] TCP TURN allocation failed")
                control_sock.close()
                return None
            else:
                print(f"[-] Unexpected response type: 0x{msg_type:04x}")
                control_sock.close()
                return None
        else:
            # 长期凭证：先发送无认证请求获取nonce和realm
            # 1. 第一次 Allocate 请求（无认证）
            tid1 = gen_tid()
            req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00"))  # REQUESTED-TRANSPORT (TCP=6)
            ])
            control_sock.send(req1)
            
            # 接收响应
            data = control_sock.recv(2000)
            msg_type, tid, attrs = parse_attrs(data)
            print("[+] First TCP resp attrs:", attrs)

            # 提取 nonce 和 realm
            nonce = attrs.get(STUN_ATTR_NONCE)   # NONCE
            server_realm = attrs.get(STUN_ATTR_REALM)   # REALM
            if nonce is None or server_realm is None:
                print("[-] No nonce/realm in response, exiting")
                return

            print(f"[+] Got nonce={nonce}, realm={server_realm}")

            # 2. 第二次 Allocate 请求
            tid2 = gen_tid()
            # 长期凭证的HMAC密钥：MD5(username:realm:password)
            key_str = f"{auth_username}:{server_realm.decode()}:{auth_password}"
            integrity_key = hashlib.md5(key_str.encode()).digest()

            attrs2 = [
                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
                stun_attr(STUN_ATTR_REALM, server_realm),              # REALM
                stun_attr(STUN_ATTR_NONCE, nonce),              # NONCE
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 6, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT (TCP=6, RFC6062规定TCP使用TCP传输)
            ]

            req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
            control_sock.send(req2)

            data = control_sock.recv(2000)
            msg_type, tid, attrs = parse_attrs(data)
            print("[+] Final TCP resp attrs:", attrs)
        
        # 检查响应状态
        if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
            print("[+] TCP TURN allocation successful")
            # 对于长期凭证，mi_algorithm 为 None，后续请求使用默认的 build_msg
            if not use_short_term_credential:
                mi_algorithm = None
            return control_sock, nonce, server_realm, integrity_key, server_address, mi_algorithm
        elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
            print("[-] TCP TURN allocation failed: Error response")
            # 检查错误码
            error_code = attrs.get(STUN_ATTR_ERROR_CODE)  # ERROR-CODE attribute
            if error_code:
                error_class = error_code[2]
                error_number = error_code[3]
                error_reason = error_code[4:].decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                
                # 处理300 (Try Alternate)错误
                if error_class == 3 and error_number == 0:  # 300 Try Alternate
                    print("[+] Received Try Alternate error, checking for alternate server...")
                    alternate_server = attrs.get(STUN_ATTR_ALTERNATE_SERVER)
                    if alternate_server:
                        alt_addr = parse_alternate_server(alternate_server)
                        if alt_addr:
                            print(f"[+] Found alternate server: {alt_addr[0]}:{alt_addr[1]}")
                            control_sock.close()
                            # 递归调用使用备用服务器
                            return allocate_tcp_single_server(alt_addr, username, password, realm, use_tls, use_short_term_credential)
                        else:
                            print("[-] Failed to parse alternate server address")
                    else:
                        print("[+] No alternate server provided")
                        control_sock.close()
                        return None
            control_sock.close()
            return None
        elif msg_type is None:
            print("[-] TCP TURN allocation failed: All authentication methods timed out or failed")
            control_sock.close()
            return None
        else:
            print(f"[-] Unexpected response type: 0x{msg_type:04x}")
            control_sock.close()
            return None
        
    except Exception as e:
        print(f"[-] TCP allocation failed: {e}")
        control_sock.close()
        return None

def allocate_tcp_udp(server_address=None, username=None, password=None, realm=None, use_tls=False, server_hostname=None, use_short_term_credential=False):
    """分配TCP连接但UDP中继的TURN地址，支持多IP备选和自动重试
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        use_tls: 是否使用TLS
        server_hostname: 服务器主机名（用于DNS发现和TLS）
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    # 如果提供了主机名，先进行DNS解析
    if server_hostname:
        print(f"[+] Discovering all IPs for {server_hostname}")
        ips = discover_turn_server_ips(server_hostname)
        if ips:
            print(f"[+] Total discovered {len(ips)} IPs: {ips}")
            print(f"[+] Trying {len(ips)} IP addresses for TCP+UDP TURN server")
        else:
            print(f"[-] Failed to discover IPs for {server_hostname}")
            return None
    else:
        # 直接使用提供的IP地址
        ips = [server_address[0]]
    
    # 尝试每个IP地址
    for i, ip in enumerate(ips, 1):
        current_address = (ip, server_address[1])
        print(f"[+] TCP+UDP Attempt {i}/{len(ips)}: Trying {current_address}")
        
        result = allocate_tcp_udp_single_server(current_address, username, password, realm, use_tls, server_hostname, use_short_term_credential)
        if result:
            print(f"[+] Successfully allocated TCP+UDP on {current_address}")
            return result
        else:
            print(f"[-] Failed to allocate TCP+UDP on {current_address}")
    
    print("[-] All TCP+UDP IP addresses failed")
    return None

def allocate_tcp_udp_single_server(server_address, username=None, password=None, realm=None, use_tls=False, server_hostname=None, use_short_term_credential=False):
    """向单个服务器分配TCP连接但UDP中继的TURN地址
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        use_tls: 是否使用TLS
        server_hostname: 服务器主机名（用于TLS）
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    # 使用传入的认证信息或默认值
    auth_username = username or USERNAME
    auth_password = password or PASSWORD
        
    # TCP TURN需要先建立TCP控制连接
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_sock.settimeout(10)
    
    try:
        # 连接到TURN服务器
        control_sock.connect(server_address)
        print(f"[+] Connected to TURN server {server_address}")
        
        # 如果使用TLS，建立SSL连接
        if use_tls:
            import ssl
            print("[+] Establishing TLS connection...")
            context = ssl.create_default_context()
            # 使用主机名而不是IP地址进行SSL握手
            ssl_hostname = server_hostname or server_address[0]
            control_sock = context.wrap_socket(control_sock, server_hostname=ssl_hostname)
            print("[+] TLS connection established")
        
        if use_short_term_credential:
            # 短期凭证：直接发送带认证的请求，不需要nonce/realm
            # 短期凭证的HMAC密钥直接使用password（OpaqueString profile）
            integrity_key = opaque_string(auth_password)
            print(f"[+] Using short-term credential mechanism")
            print(f"[+] HMAC key (password): {auth_password}")
            print(f"[+] HMAC key (bytes): {integrity_key.hex()}")
            
            attrs = [
                stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT (UDP=17)
            ]
            
            # 根据 RFC 8489 Section 9.1.2，默认情况下必须同时包含 MESSAGE-INTEGRITY-SHA256 和 MESSAGE-INTEGRITY
            tid = gen_tid()
            req = build_msg_with_short_term_credential(STUN_ALLOCATE_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
            control_sock.send(req)
            
            try:
                data = control_sock.recv(2000)
                msg_type, tid, resp_attrs = parse_attrs(data)
                print("[+] Allocate response attrs:", resp_attrs)
            except socket.timeout:
                print("[-] Timeout waiting for response")
                control_sock.close()
                return None
            
            # 检查响应状态
            if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                print("[+] TCP+UDP TURN allocation successful")
                
                # 检测服务器在响应中使用的算法类型（用于后续请求，RFC 8489 Section 9.1.5）
                has_sha256 = STUN_ATTR_MESSAGE_INTEGRITY_SHA256 in resp_attrs
                has_sha1 = STUN_ATTR_MESSAGE_INTEGRITY in resp_attrs
                
                if has_sha256:
                    mi_algorithm = 'sha256'
                    print(f"[+] Server uses MESSAGE-INTEGRITY-SHA256, subsequent requests will use SHA256 only (RFC 8489 Section 9.1.5)")
                elif has_sha1:
                    mi_algorithm = 'sha1'
                    print(f"[+] Server uses MESSAGE-INTEGRITY, subsequent requests will use SHA1 only (RFC 8489 Section 9.1.5)")
                else:
                    mi_algorithm = 'both'  # 默认
                    print(f"[!] Warning: No MI attribute in response, using method: {mi_algorithm}")
                
                # 根据 RFC 8489 Section 9.1.4，验证响应中的消息完整性
                is_valid, verified_algorithm = verify_short_term_response_integrity(data, integrity_key, expected_algorithm='both')
                if not is_valid:
                    print("[!] Response integrity verification failed per RFC 8489 Section 9.1.4")
                    # 根据 RFC 8489 Section 9.1.4，对于可靠传输，立即结束事务并报告完整性保护违规
                    print("[!] Ending transaction (reliable transport) - integrity protection violated")
                    control_sock.close()
                    return None
                
                if verified_algorithm and verified_algorithm != mi_algorithm:
                    mi_algorithm = verified_algorithm
                
                nonce = None
                server_realm = None
                return control_sock, nonce, server_realm, integrity_key, server_address, mi_algorithm
            elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                error_code = resp_attrs.get(STUN_ATTR_ERROR_CODE)
                if error_code:
                    error_class = error_code[2]
                    error_number = error_code[3]
                    error_reason = error_code[4:].decode('utf-8', errors='ignore')
                    print(f"[-] Error: {error_class}{error_number:02d} {error_reason}")
                print("[-] TCP+UDP TURN allocation failed")
                control_sock.close()
                return None
            else:
                print(f"[-] Unexpected response type: 0x{msg_type:04x}")
                control_sock.close()
                return None
        else:
            # 长期凭证：先发送无认证请求获取nonce和realm
            # 第一次分配请求（无认证）
            tid1 = gen_tid()
            attrs1 = [
                stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT (UDP=17)
            ]
            
            req1 = build_msg(STUN_ALLOCATE_REQUEST, tid1, attrs1, None, add_fingerprint=False)
            control_sock.send(req1)
            
            # 接收第一次响应
            data = control_sock.recv(2000)
            msg_type, tid, attrs = parse_attrs(data)
            print("[+] First TCP+UDP resp attrs:", attrs)
            
            # 检查响应类型
            if msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                # 检查错误代码
                error_code = attrs.get(9)
                # 检查是否是401 Unauthorized错误
                is_unauthorized = False
                if error_code:
                    # 检查错误代码格式: 前2字节是错误类，第3字节是错误号
                    if len(error_code) >= 4:
                        error_class = error_code[2]
                        error_number = error_code[3]
                        if error_class == 4 and error_number == 1:  # 401 Unauthorized
                            is_unauthorized = True
                    # 也检查文本形式的错误
                    if b"Unauthorized" in error_code or b"401" in error_code:
                        is_unauthorized = True
                
                if is_unauthorized:
                    print("[+] Got nonce and realm for authentication")
                    nonce = attrs.get(21)
                    server_realm = attrs.get(20)
                    
                    if nonce is not None and server_realm is not None:
                        print(f"[+] Got nonce={nonce}, realm={server_realm}")
                        
                        # 计算完整性密钥
                        key_str = f"{auth_username}:{server_realm.decode()}:{auth_password}"
                        print(f"[+] HMAC key string: {key_str}")
                        integrity_key = hashlib.md5(key_str.encode()).digest()
                        print(f"[+] HMAC key: {integrity_key.hex()}")
                        
                        # 第二次分配请求（带认证）
                        tid2 = gen_tid()
                        attrs2 = [
                            stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),   # USERNAME
                            stun_attr(STUN_ATTR_REALM, server_realm),              # REALM
                            stun_attr(STUN_ATTR_NONCE, nonce),              # NONCE
                            stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT (UDP=17)
                        ]

                        req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)
                        control_sock.send(req2)
                        
                        # 接收第二次响应
                        data = control_sock.recv(2000)
                        msg_type, tid, attrs = parse_attrs(data)
                        print("[+] Final TCP+UDP resp attrs:", attrs)
                    
                        # 检查是否成功
                        if msg_type == STUN_ALLOCATE_SUCCESS_RESPONSE:
                            print("[+] TCP+UDP TURN allocation successful")
                            return control_sock, nonce, server_realm, integrity_key, server_address
                        elif msg_type == STUN_ALLOCATE_ERROR_RESPONSE:
                            error_code = attrs.get(9)
                            if error_code:
                                # 解析错误代码
                                if len(error_code) >= 4:
                                    error_class = error_code[2]
                                    error_number = error_code[3]
                                    error_text = error_code[4:].decode('utf-8', errors='ignore')
                                    print(f"[-] TCP+UDP TURN allocation failed: Error response")
                                    print(f"[-] Error: {error_class}{error_number:02d} {error_text}")
                                else:
                                    error_text = error_code[3:].decode('utf-8', errors='ignore')
                                    print(f"[-] TCP+UDP TURN allocation failed: Error response")
                                    print(f"[-] Error: {error_text}")
                            control_sock.close()
                            return None
                        else:
                            print(f"[-] Unexpected response type: 0x{msg_type:04x}")
                            control_sock.close()
                            return None
                    else:
                        print("[-] Missing nonce or realm in response")
                        control_sock.close()
                        return None
                elif error_code and b"Try Alternate" in error_code:
                    print("[+] Got Try Alternate response")
                    # 解析ALTERNATE-SERVER属性
                    alt_server = attrs.get(0x8023)  # ALTERNATE-SERVER
                    if alt_server:
                        alt_addr = parse_alternate_server(alt_server)
                        if alt_addr:
                            print(f"[+] Trying alternate server: {alt_addr}")
                            control_sock.close()
                            # 递归尝试备用服务器
                            return allocate_tcp_udp_single_server(alt_addr, username, password, realm, use_tls, server_hostname, use_short_term_credential)
                        else:
                            print("[-] Failed to parse alternate server address")
                    else:
                        print("[+] No alternate server provided")
                    control_sock.close()
                    return None
                else:
                    print("[-] Unexpected error response")
                    control_sock.close()
                    return None
            else:
                print(f"[-] Unexpected response type: 0x{msg_type:04x}")
                control_sock.close()
                return None
        
    except Exception as e:
        print(f"[-] TCP+UDP allocation failed: {e}")
        control_sock.close()
        return None


def allocate_tcp(server_address=None, username=None, password=None, realm=None, use_tls=False, server_hostname=None, use_short_term_credential=False):
    """分配TCP TURN中继地址，支持多IP备选和自动重试
    
    Args:
        server_address: TURN服务器地址 (ip, port)
        username: 用户名
        password: 密码
        realm: 认证域（长期凭证需要）
        use_tls: 是否使用TLS
        server_hostname: 服务器主机名（用于DNS发现）
        use_short_term_credential: 是否使用短期凭证机制（默认False，使用长期凭证）
    """
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    # 获取服务器主机名用于DNS发现
    if server_hostname is None:
        server_hostname = server_address[0]
    
    # 发现所有IP地址
    server_ips = discover_turn_server_ips(server_hostname)
    server_port = server_address[1]
    
    print(f"[+] Trying {len(server_ips)} IP addresses for TCP TURN server")
    
    # 尝试每个IP地址
    for i, ip in enumerate(server_ips):
        current_address = (ip, server_port)
        print(f"[+] TCP Attempt {i+1}/{len(server_ips)}: Trying {current_address}")
        
        result = allocate_tcp_single_server(current_address, username, password, realm, use_tls, use_short_term_credential)
        if result:
            print(f"[+] Successfully allocated TCP on {current_address}")
            return result
        else:
            print(f"[-] Failed to allocate TCP on {current_address}")
    
    print("[-] All TCP IP addresses failed")
    return None

def create_permission(sock, nonce, realm, integrity_key, peer_ip, peer_port, server_address=None, username=None, mi_algorithm=None):
    """创建权限，允许向指定对等方发送数据
    
    Args:
        mi_algorithm: 消息完整性算法类型 ('sha256', 'sha1', 'both', 或 None)
                      对于短期凭证，必须与服务器在初始响应中使用的算法匹配
                      对于长期凭证，应为 None（使用默认的 build_msg）
    """
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Creating permission for {peer_ip}:{peer_port}")
    
    # 解析对等方地址（支持域名）
    resolved_peer_ip = resolve_peer_address(peer_ip)
    if not resolved_peer_ip:
        print(f"[-] Failed to resolve peer address {peer_ip}")
        return False
    
    # 将IP地址转换为网络字节序
    peer_addr = socket.inet_aton(resolved_peer_ip)
    # XOR编码地址（使用magic cookie）
    xor_port = peer_port ^ (STUN_MAGIC_COOKIE >> 16)
    xor_addr = struct.pack("!BBH", 0, 1, xor_port) + peer_addr  # IPv4, XOR端口，IP地址
    
    # XOR编码IP地址
    xor_ip = bytes([peer_addr[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)])
    xor_addr = struct.pack("!BBH", 0, 1, xor_port) + xor_ip
    
    # 使用传入的用户名或默认用户名
    auth_username = username or USERNAME
    
    tid = gen_tid()
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
    ]
    
    # 短期凭证不需要 REALM 和 NONCE
    if realm is not None:
        attrs.append(stun_attr(STUN_ATTR_REALM, realm))
    if nonce is not None:
        attrs.append(stun_attr(STUN_ATTR_NONCE, nonce))
    
    attrs.append(stun_attr(STUN_ATTR_XOR_PEER_ADDRESS, xor_addr))
    
    # 短期凭证（nonce 和 realm 为 None）必须使用服务器在初始响应中使用的算法
    if nonce is None and realm is None:
        if mi_algorithm == 'sha256':
            req = build_msg_with_short_term_credential_sha256_only(STUN_CREATE_PERMISSION_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        elif mi_algorithm == 'sha1':
            req = build_msg_with_short_term_credential_sha1_only(STUN_CREATE_PERMISSION_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        else:
            # 默认使用 both（仅在初始请求时）
            req = build_msg_with_short_term_credential(STUN_CREATE_PERMISSION_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    else:
        req = build_msg(STUN_CREATE_PERMISSION_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    
    # 检查是否为SSL套接字（更准确的检测方法）
    if hasattr(sock, '_sslobj') or sock.__class__.__name__ == 'SSLSocket':
        # SSL/TLS套接字
        sock.send(req)
        data = sock.recv(2000)
    else:
        # UDP套接字
        sock.sendto(req, server_address)
        data, _ = sock.recvfrom(2000)
    
    msg_type, tid, attrs = parse_attrs(data)
    print("[+] CreatePermission response:", attrs)
    
    # 检查是否有错误响应
    if msg_type == STUN_CREATE_PERMISSION_ERROR_RESPONSE:
        error_code = attrs.get(9)  # STUN_ATTR_ERROR_CODE
        if error_code:
            error_code_int = struct.unpack("!H", error_code[:2])[0]
            error_reason = error_code[4:].decode('utf-8', errors='ignore')
            print(f"[-] CreatePermission failed: {error_code_int} {error_reason}")
            return False
    
    return True

def channel_bind(sock, nonce, realm, integrity_key, peer_ip, peer_port, channel_number, server_address=None, username=None, mi_algorithm=None):
    """绑定通道号到对等方地址
    
    Args:
        mi_algorithm: 消息完整性算法类型 ('sha256', 'sha1', 'both', 或 None)
                      对于短期凭证，必须与服务器在初始响应中使用的算法匹配
                      对于长期凭证，应为 None（使用默认的 build_msg）
    """
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Binding channel {channel_number} to {peer_ip}:{peer_port}")
    
    # 解析对等方地址（支持域名）
    resolved_peer_ip = resolve_peer_address(peer_ip)
    if not resolved_peer_ip:
        print(f"[-] Failed to resolve peer address {peer_ip}")
        return False
    
    # 将IP地址转换为网络字节序
    peer_addr = socket.inet_aton(resolved_peer_ip)
    # XOR编码地址（使用magic cookie）
    xor_port = peer_port ^ (STUN_MAGIC_COOKIE >> 16)
    
    # XOR编码IP地址
    xor_ip = bytes([peer_addr[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)])
    xor_addr = struct.pack("!BBH", 0, 1, xor_port) + xor_ip
    
    # 使用传入的用户名或默认用户名
    auth_username = username or USERNAME
    
    tid = gen_tid()
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
    ]
    
    # 短期凭证不需要 REALM 和 NONCE
    if realm is not None:
        attrs.append(stun_attr(STUN_ATTR_REALM, realm))
    if nonce is not None:
        attrs.append(stun_attr(STUN_ATTR_NONCE, nonce))
    
    attrs.extend([
        stun_attr(STUN_ATTR_CHANNEL_NUMBER, struct.pack("!HH", channel_number, 0)),
        stun_attr(STUN_ATTR_XOR_PEER_ADDRESS, xor_addr),
    ])
    
    # 短期凭证（nonce 和 realm 为 None）必须使用服务器在初始响应中使用的算法
    if nonce is None and realm is None:
        if mi_algorithm == 'sha256':
            req = build_msg_with_short_term_credential_sha256_only(STUN_CHANNEL_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        elif mi_algorithm == 'sha1':
            req = build_msg_with_short_term_credential_sha1_only(STUN_CHANNEL_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        else:
            # 默认使用 both（仅在初始请求时）
            req = build_msg_with_short_term_credential(STUN_CHANNEL_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    else:
        req = build_msg(STUN_CHANNEL_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    
    # 检查是否为SSL套接字（更准确的检测方法）
    if hasattr(sock, '_sslobj') or sock.__class__.__name__ == 'SSLSocket':
        # SSL/TLS套接字
        sock.send(req)
        data = sock.recv(2000)
    else:
        # UDP套接字
        sock.sendto(req, server_address)
        data, _ = sock.recvfrom(2000)
    
    msg_type, tid, attrs = parse_attrs(data)
    print("[+] ChannelBind response:", attrs)
    
    # 检查是否有错误响应
    if msg_type == STUN_CHANNEL_BIND_ERROR_RESPONSE:
        error_code = attrs.get(9)  # STUN_ATTR_ERROR_CODE
        if error_code:
            error_code_int = struct.unpack("!H", error_code[:2])[0]
            error_reason = error_code[4:].decode('utf-8', errors='ignore')
            print(f"[-] ChannelBind failed: {error_code_int} {error_reason}")
            return False
    
    return True

def channel_data_tcp(control_sock, channel_number, data, server_address=None):
    """通过TCP控制连接发送ChannelData消息"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Sending data through channel {channel_number}: {data}")
    
    # ChannelData消息格式：通道号(2字节) + 数据长度(2字节) + 数据
    channel_data_msg = struct.pack("!HH", channel_number, len(data)) + data
    
    try:
        control_sock.send(channel_data_msg)
        print("[+] ChannelData sent successfully")
        return True
    except Exception as e:
        print(f"[-] Failed to send ChannelData: {e}")
        return False

def channel_data(sock, channel_number, data, server_address=None):
    """通过通道发送数据"""
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Sending data through channel {channel_number}: {data}")
    
    # ChannelData消息格式：通道号(2字节) + 数据长度(2字节) + 数据
    channel_data_msg = struct.pack("!HH", channel_number, len(data)) + data
    
    sock.sendto(channel_data_msg, server_address)
    print("[+] ChannelData sent successfully")
    
    return True

def tcp_connect(control_sock, nonce, realm, integrity_key, peer_ip, peer_port, username=None, mi_algorithm=None):
    """发起TCP连接到对等方 (RFC 6062 Connect请求)
    
    Args:
        mi_algorithm: 消息完整性算法类型 ('sha256', 'sha1', 'both', 或 None)
                      对于短期凭证，必须与服务器在初始响应中使用的算法匹配
                      对于长期凭证，应为 None（使用默认的 build_msg）
    """
    print(f"[+] Initiating TCP connection to {peer_ip}:{peer_port}")
    
    # 解析对等方地址（支持域名）
    resolved_peer_ip = resolve_peer_address(peer_ip)
    if not resolved_peer_ip:
        print(f"[-] Failed to resolve peer address {peer_ip}")
        return None
    
    # 将IP地址转换为网络字节序
    peer_addr = socket.inet_aton(resolved_peer_ip)
    # XOR编码地址（使用magic cookie）
    xor_port = peer_port ^ (STUN_MAGIC_COOKIE >> 16)
    
    # XOR编码IP地址
    xor_ip = bytes([peer_addr[i] ^ ((STUN_MAGIC_COOKIE >> (8*(3-i))) & 0xFF) for i in range(4)])
    xor_addr = struct.pack("!BBH", 0, 1, xor_port) + xor_ip
    
    tid = gen_tid()
    # 使用传入的用户名或默认值
    auth_username = username or USERNAME
    print(f"[+] Using username for Connect request: {auth_username}")
    
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
    ]
    
    # 短期凭证不需要 REALM 和 NONCE
    if realm is not None:
        attrs.append(stun_attr(STUN_ATTR_REALM, realm))
    if nonce is not None:
        attrs.append(stun_attr(STUN_ATTR_NONCE, nonce))
    
    attrs.append(stun_attr(STUN_ATTR_XOR_PEER_ADDRESS, xor_addr))
    
    # 短期凭证（nonce 和 realm 为 None）必须使用服务器在初始响应中使用的算法
    if nonce is None and realm is None:
        if mi_algorithm == 'sha256':
            req = build_msg_with_short_term_credential_sha256_only(STUN_CONNECT_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        elif mi_algorithm == 'sha1':
            req = build_msg_with_short_term_credential_sha1_only(STUN_CONNECT_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        else:
            # 默认使用 both（仅在初始请求时）
            req = build_msg_with_short_term_credential(STUN_CONNECT_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    else:
        req = build_msg(STUN_CONNECT_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    control_sock.send(req)
    
    # 接收Connect响应
    data = control_sock.recv(2000)
    msg_type, tid, attrs = parse_attrs(data)
    print("[+] Connect response:", attrs)
    
    # 检查响应类型
    if msg_type == 0x010a:  # Connect Success Response (0x010a)
        print("[+] Connect successful")
        connection_id = attrs.get(STUN_ATTR_CONNECTION_ID)
        if connection_id:
            conn_id = struct.unpack("!I", connection_id)[0]
            print(f"[+] Got connection ID: {conn_id}")
            return conn_id
        else:
            print("[-] No connection ID in Connect response")
            print("[-] Response attributes keys:", list(attrs.keys()))
            return None
    elif msg_type == 0x011a:  # Connect Error Response (0x011a)
        print("[-] Connect error")
        error_code = attrs.get(STUN_ATTR_ERROR_CODE)
        if error_code:
            if len(error_code) >= 4:
                error_class = error_code[2]
                error_number = error_code[3]
                error_text = error_code[4:].decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_class}{error_number:02d} {error_text}")
            else:
                error_text = error_code.decode('utf-8', errors='ignore')
                print(f"[-] Error: {error_text}")
        print("[-] Response attributes keys:", list(attrs.keys()))
        return None
    else:
        print(f"[-] Unexpected response type: 0x{msg_type:04x}")
        print("[-] Response attributes keys:", list(attrs.keys()))
        return None

def tcp_connection_bind(control_sock, nonce, realm, integrity_key, connection_id, server_address=None, username=None, mi_algorithm=None):
    """绑定客户端数据连接到对等方连接 (RFC 6062 ConnectionBind请求)
    
    Args:
        mi_algorithm: 消息完整性算法类型 ('sha256', 'sha1', 'both', 或 None)
                      对于短期凭证，必须与服务器在初始响应中使用的算法匹配
                      对于长期凭证，应为 None（使用默认的 build_msg）
    """
    if server_address is None:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
        
    print(f"[+] Binding data connection with connection ID {connection_id}")
    
    # 使用传入的用户名或默认值
    auth_username = username or USERNAME
    
    tid = gen_tid()
    attrs = [
        stun_attr(STUN_ATTR_USERNAME, auth_username.encode()),
    ]
    
    # 短期凭证不需要 REALM 和 NONCE
    if realm is not None:
        attrs.append(stun_attr(STUN_ATTR_REALM, realm))
    if nonce is not None:
        attrs.append(stun_attr(STUN_ATTR_NONCE, nonce))
    
    attrs.append(stun_attr(STUN_ATTR_CONNECTION_ID, struct.pack("!I", connection_id)))
    
    # 短期凭证（nonce 和 realm 为 None）必须使用服务器在初始响应中使用的算法
    if nonce is None and realm is None:
        if mi_algorithm == 'sha256':
            req = build_msg_with_short_term_credential_sha256_only(STUN_CONNECTION_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        elif mi_algorithm == 'sha1':
            req = build_msg_with_short_term_credential_sha1_only(STUN_CONNECTION_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
        else:
            # 默认使用 both（仅在初始请求时）
            req = build_msg_with_short_term_credential(STUN_CONNECTION_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    else:
        req = build_msg(STUN_CONNECTION_BIND_REQUEST, tid, attrs, integrity_key, add_fingerprint=True)
    control_sock.send(req)
    
    # 接收ConnectionBind响应
    data = control_sock.recv(2000)
    msg_type, tid, attrs = parse_attrs(data)
    print("[+] ConnectionBind response:", attrs)
    
    return True

def tcp_send_data(data_sock, data):
    """通过TCP数据连接发送数据"""
    print(f"[+] Sending TCP data: {data}")
    try:
        data_sock.send(data)
        print("[+] TCP data sent successfully")
        return True
    except Exception as e:
        print(f"[-] Failed to send TCP data: {e}")
        return False

def tcp_receive_data(data_sock, buffer_size=1024):
    """从TCP数据连接接收数据"""
    try:
        data = data_sock.recv(buffer_size)
        if data:
            print(f"[+] Received TCP data: {data}")
            return data
        else:
            print("[+] TCP connection closed by peer")
            return None
    except Exception as e:
        print(f"[-] Failed to receive TCP data: {e}")
        return None

def main(target_ip, target_port, turn_server=None, turn_port=None, username=None, password=None, realm=None):
    """主函数：演示UDP TURN客户端功能"""
    print("[+] Starting UDP TURN client...")
    
    # 解析TURN服务器地址
    if turn_server:
        server_address = resolve_server_address(turn_server, turn_port or DEFAULT_TURN_PORT)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return
    else:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    print(f"[+] Using TURN server: {server_address}")
    
    # 1. 分配TURN中继地址
    result = allocate(server_address, username, password, realm, turn_server)
    if not result:
        print("[-] Failed to allocate TURN relay")
        return
    
    sock, nonce, realm, integrity_key, actual_server_address = result
    print("[+] TURN allocation successful")
    
    # 2. 配置目标对等方
    import random
    channel_number = random.randint(0x4000, 0x4FFF)  # 随机生成通道号（必须在0x4000-0x4FFF范围内）
    
    # 3. 创建权限（使用实际连接的服务器地址和正确的用户名）
    if not create_permission(sock, nonce, realm, integrity_key, target_ip, target_port, actual_server_address, username):
        print("[-] Failed to create permission")
        return
    
    # 4. 绑定通道（使用实际连接的服务器地址和正确的用户名）
    if not channel_bind(sock, nonce, realm, integrity_key, target_ip, target_port, channel_number, actual_server_address, username):
        print("[-] Failed to bind channel")
        return
    
    # 5. 通过通道发送数据
    test_data = b"Hello from UDP TURN client!"
    if not channel_data(sock, channel_number, test_data, actual_server_address):
        print("[-] Failed to send channel data")
        return
    
    print("[+] UDP TURN client demo completed successfully")
    
    # 关闭socket
    sock.close()

def main_tcp_udp(target_ip, target_port, turn_server=None, turn_port=None, username=None, password=None, realm=None, use_tls=False):
    """TCP连接 + UDP中继的TURN客户端演示"""
    print("=== Running TCP+UDP TURN Demo ===")
    print(f"Target: {target_ip}:{target_port}")
    if turn_server:
        print(f"TURN Server: {turn_server}:{turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    
    print("[+] Starting TCP+UDP TURN client...")
    
    # 确定服务器地址
    if turn_server:
        server_address = (turn_server, turn_port or DEFAULT_TURN_PORT)
    else:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    # 1. 分配TCP TURN中继地址（但使用UDP中继）
    result = allocate_tcp_udp(server_address, username, password, realm, use_tls, turn_server)
    if not result:
        print("[-] Failed to allocate TCP+UDP TURN relay")
        return
    
    control_sock, nonce, realm, integrity_key, actual_server_address = result
    print("[+] TCP+UDP TURN allocation successful")
    
    # 2. 创建权限
    if not create_permission(control_sock, nonce, realm, integrity_key, target_ip, target_port, actual_server_address, username):
        print("[-] Failed to create permission")
        control_sock.close()
        return
    
    # 3. 绑定通道
    import random
    channel_number = random.randint(0x4000, 0x4FFF)
    if not channel_bind(control_sock, nonce, realm, integrity_key, target_ip, target_port, channel_number, actual_server_address, username):
        print("[-] Failed to bind channel")
        control_sock.close()
        return
    
    # 4. 通过通道发送数据
    test_data = b'Hello from TCP+UDP TURN client!'
    if not channel_data_tcp(control_sock, channel_number, test_data, actual_server_address):
        print("[-] Failed to send channel data")
        control_sock.close()
        return
    
    print("[+] TCP+UDP TURN client demo completed successfully")
    control_sock.close()


def main_tcp(target_ip, target_port, turn_server=None, turn_port=None, username=None, password=None, realm=None, use_tls=False):
    """主函数：演示TCP TURN客户端功能"""
    print("[+] Starting TCP TURN client...")
    
    # 解析TURN服务器地址
    if turn_server:
        server_address = resolve_server_address(turn_server, turn_port or DEFAULT_TURN_PORT)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return
    else:
        server_address = (DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT)
    
    print(f"[+] Using TURN server: {server_address}")
    
    # 1. 分配TCP TURN中继地址
    result = allocate_tcp(server_address, username, password, realm, use_tls, turn_server)
    if not result:
        print("[-] Failed to allocate TCP TURN relay")
        return
    
    control_sock, nonce, realm, integrity_key, actual_server_address = result
    print("[+] TCP TURN allocation successful")
    
    # 3. 发起TCP连接到对等方
    connection_id = tcp_connect(control_sock, nonce, realm, integrity_key, target_ip, target_port, username)
    if not connection_id:
        print("[-] Failed to initiate TCP connection")
        control_sock.close()
        return
    
    # 4. 建立数据连接（RFC6062要求）
    print("[+] Establishing data connection to TURN server...")
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_sock.settimeout(10)
    
    try:
        # 建立新的TCP连接到TURN服务器作为数据连接
        data_sock.connect(actual_server_address)
        print(f"[+] Data connection established to {actual_server_address}")
        
        # 在数据连接上发送ConnectionBind请求
        if not tcp_connection_bind(data_sock, nonce, realm, integrity_key, connection_id, actual_server_address, username):
            print("[-] Failed to bind data connection")
            data_sock.close()
            control_sock.close()
            return
        
        print("[+] Data connection bound successfully")
        
        # 5. 发送测试数据
        test_data = b"Hello from TCP TURN client!"
        print(f"[+] Sending TCP data: {test_data}")
        data_sock.send(test_data)
        
        # 6. 接收响应数据
        print("[+] Waiting for response...")
        try:
            response = data_sock.recv(1024)
            if response:
                print(f"[+] Received response: {response}")
            else:
                print("[+] Connection closed by peer")
        except socket.timeout:
            print("[+] No response received (timeout)")
        
        print("[+] TCP TURN client demo completed successfully")
        
    except Exception as e:
        print(f"[-] Failed to establish data connection: {e}")
    finally:
        # 关闭连接
        data_sock.close()
        control_sock.close()

    

def test():
    
    tid2 = bytes.fromhex("53596a9f080f78580957e6d3")
    key_str = f"demo:anjhz3.com:demoPass123"
    integrity_key = hashlib.md5(key_str.encode()).digest()

    attrs2 = [
        stun_attr(STUN_ATTR_USERNAME, USERNAME.encode()),   # USERNAME
        stun_attr(STUN_ATTR_REALM, b"anjhz3.com"),              # REALM
        stun_attr(STUN_ATTR_NONCE, b'c4a0ab8162347fad'),              # NONCE
        stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, struct.pack("!B3s", 17, b"\x00\x00\x00")),  # REQUESTED-TRANSPORT
    ]

    req2 = build_msg(STUN_ALLOCATE_REQUEST, tid2, attrs2, integrity_key, add_fingerprint=True)

    
    
if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='TURN客户端实现 - 支持UDP和TCP传输协议')
    parser.add_argument('mode', nargs='?', choices=['udp', 'tcp-udp', 'tcp'], default='udp',
                       help='运行模式: udp (UDP TURN), tcp-udp (TCP连接+UDP中继), tcp (TCP TURN)')
    parser.add_argument('--target-ip', required=True, help='目标IP地址')
    parser.add_argument('--target-port', type=int, required=True, help='目标端口')
    parser.add_argument('--turn-server', help='TURN服务器地址（域名或IP）')
    parser.add_argument('--turn-port', type=int, help='TURN服务器端口')
    parser.add_argument('--username', help='TURN服务器用户名')
    parser.add_argument('--password', help='TURN服务器密码')
    parser.add_argument('--realm', help='TURN服务器认证域')
    parser.add_argument('--tls', action='store_true', help='使用TLS加密连接')
    
    args = parser.parse_args()
    
    print(f"=== Running {args.mode.upper()} TURN Demo ===")
    print(f"Target: {args.target_ip}:{args.target_port}")
    if args.turn_server:
        print(f"TURN Server: {args.turn_server}:{args.turn_port or DEFAULT_TURN_PORT}")
    else:
        print(f"TURN Server: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT} (default)")
    
    if args.mode == "udp":
        main(args.target_ip, args.target_port, args.turn_server, args.turn_port, args.username, args.password, args.realm)
    elif args.mode == "tcp-udp":
        main_tcp_udp(args.target_ip, args.target_port, args.turn_server, args.turn_port, args.username, args.password, args.realm, args.tls)
    elif args.mode == "tcp":
        main_tcp(args.target_ip, args.target_port, args.turn_server, args.turn_port, args.username, args.password, args.realm, args.tls)
    
