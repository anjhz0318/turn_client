#!/usr/bin/env python3
"""
UDP 协议数据包字典
包含各种常见 UDP 协议的数据包，用于协议探测
"""

import struct
import random
import os
import zlib

# UDP 协议数据包字典
# 格式: {protocol_name: {'packet': bytes, 'description': str, 'default_port': int}}
UDP_PROTOCOL_PACKETS = {
    'dns_query': {
        'packet': None,  # 动态生成
        'description': 'DNS 查询请求（查询 A 记录）',
        'default_port': 53,
        'generate': lambda: _generate_dns_query()
    },
    'dns_query_aaaa': {
        'packet': None,
        'description': 'DNS 查询请求（查询 AAAA 记录）',
        'default_port': 53,
        'generate': lambda: _generate_dns_query_aaaa()
    },
    'dhcp_discover': {
        'packet': None,
        'description': 'DHCP Discover 请求',
        'default_port': 67,
        'generate': lambda: _generate_dhcp_discover()
    },
    'snmp_get_request': {
        'packet': None,
        'description': 'SNMP GetRequest（查询系统描述）',
        'default_port': 161,
        'generate': lambda: _generate_snmp_get_request()
    },
    'ntp_request': {
        'packet': None,
        'description': 'NTP 时间同步请求',
        'default_port': 123,
        'generate': lambda: _generate_ntp_request()
    },
    'tftp_read_request': {
        'packet': None,
        'description': 'TFTP 读请求',
        'default_port': 69,
        'generate': lambda: _generate_tftp_read_request()
    },
    'syslog': {
        'packet': None,
        'description': 'Syslog 消息',
        'default_port': 514,
        'generate': lambda: _generate_syslog()
    },
    'netbios_name_query': {
        'packet': None,
        'description': 'NetBIOS 名称查询',
        'default_port': 137,
        'generate': lambda: _generate_netbios_name_query()
    },
    'mdns_query': {
        'packet': None,
        'description': 'mDNS 查询请求',
        'default_port': 5353,
        'generate': lambda: _generate_mdns_query()
    },
    'ssdp_discover': {
        'packet': None,
        'description': 'SSDP 发现请求',
        'default_port': 1900,
        'generate': lambda: _generate_ssdp_discover()
    },
    'coap_get': {
        'packet': None,
        'description': 'CoAP GET 请求',
        'default_port': 5683,
        'generate': lambda: _generate_coap_get()
    },
    'openvpn_handshake': {
        'packet': None,
        'description': 'OpenVPN 握手数据包',
        'default_port': 1194,
        'generate': lambda: _generate_openvpn_handshake()
    },
    'radius_access_request': {
        'packet': None,
        'description': 'RADIUS Access-Request',
        'default_port': 1812,
        'generate': lambda: _generate_radius_access_request()
    },
    'tacacs_authentication': {
        'packet': None,
        'description': 'TACACS+ 认证请求',
        'default_port': 49,
        'generate': lambda: _generate_tacacs_authentication()
    },
    'kerberos_udp': {
        'packet': None,
        'description': 'Kerberos UDP 请求',
        'default_port': 88,
        'generate': lambda: _generate_kerberos_udp()
    },
    'iscsi_udp': {
        'packet': None,
        'description': 'iSCSI UDP 数据包',
        'default_port': 3260,
        'generate': lambda: _generate_iscsi_udp()
    },
    'weave_net_udp': {
        'packet': None,
        'description': 'Weave Net UDP 探测包',
        'default_port': 6783,
        'generate': lambda: _generate_weave_net_udp()
    },
    'weave_net_udp_alt': {
        'packet': None,
        'description': 'Weave Net UDP 探测包（备用端口）',
        'default_port': 6784,
        'generate': lambda: _generate_weave_net_udp()
    },
    'flannel_udp_backend': {
        'packet': None,
        'description': 'Flannel UDP backend 探测包',
        'default_port': 8285,
        'generate': lambda: _generate_flannel_udp_backend()
    },
    'flannel_vxlan': {
        'packet': None,
        'description': 'Flannel VXLAN 探测包',
        'default_port': 8472,
        'generate': lambda: _generate_flannel_vxlan()
    },
    'stun_binding_request': {
        'packet': None,
        'description': 'STUN Binding Request（RFC 5389）',
        'default_port': 3478,
        'generate': lambda: _generate_stun_binding_request()
    },
    'stun_binding_request_fingerprint': {
        'packet': None,
        'description': 'STUN Binding Request with Fingerprint（RFC 5389）',
        'default_port': 3478,
        'generate': lambda: _generate_stun_binding_request_fingerprint()
    },
    'turn_allocate_request': {
        'packet': None,
        'description': 'TURN Allocate Request（RFC 8656）',
        'default_port': 3478,
        'generate': lambda: _generate_turn_allocate_request()
    },
    'empty': {
        'packet': b'',
        'description': '空 UDP 数据包',
        'default_port': None,
        'generate': lambda: b''
    }
}


def _generate_dns_query():
    """生成 DNS A 记录查询请求"""
    # DNS 头部
    transaction_id = random.randint(0, 65535)
    flags = 0x0100  # 标准查询，递归期望
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0
    
    header = struct.pack('!HHHHHH', transaction_id, flags, questions, 
                        answer_rrs, authority_rrs, additional_rrs)
    
    # 查询部分：www.example.com
    query_name = b'\x03www\x07example\x03com\x00'
    query_type = struct.pack('!H', 1)  # A 记录
    query_class = struct.pack('!H', 1)  # IN
    
    return header + query_name + query_type + query_class


def _generate_dns_query_aaaa():
    """生成 DNS AAAA 记录查询请求"""
    transaction_id = random.randint(0, 65535)
    flags = 0x0100
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0
    
    header = struct.pack('!HHHHHH', transaction_id, flags, questions, 
                        answer_rrs, authority_rrs, additional_rrs)
    
    query_name = b'\x03www\x07example\x03com\x00'
    query_type = struct.pack('!H', 28)  # AAAA 记录
    query_class = struct.pack('!H', 1)  # IN
    
    return header + query_name + query_type + query_class


def _generate_dhcp_discover():
    """生成 DHCP Discover 请求"""
    # DHCP 消息类型：Discover (1)
    op = 1  # BOOTREQUEST
    htype = 1  # Ethernet
    hlen = 6  # MAC 地址长度
    hops = 0
    xid = random.randint(0, 0xFFFFFFFF)
    secs = 0
    flags = 0
    ciaddr = b'\x00\x00\x00\x00'
    yiaddr = b'\x00\x00\x00\x00'
    siaddr = b'\x00\x00\x00\x00'
    giaddr = b'\x00\x00\x00\x00'
    chaddr = b'\x00' * 16  # MAC 地址（填充到16字节）
    sname = b'\x00' * 64
    file = b'\x00' * 128
    
    # DHCP 选项
    magic_cookie = b'\x63\x82\x53\x63'
    option_message_type = b'\x35\x01\x01'  # Message Type: Discover
    option_end = b'\xff'
    
    packet = struct.pack('!BBBBLHH', op, htype, hlen, hops, xid, secs, flags)
    packet += ciaddr + yiaddr + siaddr + giaddr + chaddr + sname + file
    packet += magic_cookie + option_message_type + option_end
    
    return packet


def _generate_snmp_get_request():
    """生成 SNMP GetRequest"""
    # 简化的 SNMP GetRequest（版本 2c）
    version = 1  # SNMPv2c
    community = b'public'
    pdu_type = 0xa0  # GetRequest-PDU
    request_id = random.randint(0, 0xFFFFFFFF)
    error_status = 0
    error_index = 0
    
    # 简化的 OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
    oid = b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'
    value = b'\x05\x00'  # Null
    
    # 简化的 ASN.1 编码（实际应该使用完整的 BER 编码）
    # 这里提供一个基本的 SNMP 数据包结构
    packet = struct.pack('!B', version)
    packet += struct.pack('!B', len(community)) + community
    packet += struct.pack('!B', pdu_type)
    packet += struct.pack('!L', request_id)
    packet += struct.pack('!B', error_status)
    packet += struct.pack('!B', error_index)
    packet += oid + value
    
    return packet


def _generate_ntp_request():
    """生成 NTP 请求数据包"""
    # NTP 头部（简化版）
    li_vn_mode = (0 << 6) | (4 << 3) | (3)  # LI=0, VN=4, Mode=3 (Client)
    stratum = 0
    poll = 4
    precision = 0xFA
    root_delay = b'\x00' * 4
    root_dispersion = b'\x00' * 4
    reference_id = b'\x00' * 4
    reference_timestamp = b'\x00' * 8
    originate_timestamp = b'\x00' * 8
    receive_timestamp = b'\x00' * 8
    transmit_timestamp = b'\x00' * 8
    
    packet = struct.pack('!BBBB', li_vn_mode, stratum, poll, precision)
    packet += root_delay + root_dispersion + reference_id
    packet += reference_timestamp + originate_timestamp
    packet += receive_timestamp + transmit_timestamp
    
    return packet


def _generate_tftp_read_request():
    """生成 TFTP 读请求"""
    opcode = 1  # RRQ (Read Request)
    filename = b'config.txt'
    mode = b'octet'
    
    packet = struct.pack('!H', opcode)
    packet += filename + b'\x00'
    packet += mode + b'\x00'
    
    return packet


def _generate_syslog():
    """生成 Syslog 消息"""
    # Syslog 格式: <PRI>timestamp hostname tag: message
    priority = 16  # Local0.Info
    timestamp = b'Nov 17 22:30:00'
    hostname = b'test'
    tag = b'testapp'
    message = b'Test syslog message'
    
    packet = b'<' + str(priority).encode() + b'>'
    packet += timestamp + b' ' + hostname + b' '
    packet += tag + b': ' + message
    
    return packet


def _generate_netbios_name_query():
    """生成 NetBIOS 名称查询请求"""
    transaction_id = random.randint(0, 65535)
    flags = 0x0110  # Standard query, recursion desired
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0
    
    header = struct.pack('!HHHHHH', transaction_id, flags, questions,
                        answer_rrs, authority_rrs, additional_rrs)
    
    # NetBIOS 名称查询（编码格式）
    name = b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
    query_type = struct.pack('!H', 0x0020)  # NBSTAT
    query_class = struct.pack('!H', 0x0001)  # IN
    
    return header + name + query_type + query_class


def _generate_mdns_query():
    """生成 mDNS 查询请求"""
    transaction_id = random.randint(0, 65535)
    flags = 0x0000  # 标准查询
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0
    
    header = struct.pack('!HHHHHH', transaction_id, flags, questions,
                        answer_rrs, authority_rrs, additional_rrs)
    
    # 查询 _services._dns-sd._udp.local
    query_name = b'\x08_services\x07_dns-sd\x04_udp\x05local\x00'
    query_type = struct.pack('!H', 12)  # PTR
    query_class = struct.pack('!H', 1)  # IN
    
    return header + query_name + query_type + query_class


def _generate_ssdp_discover():
    """生成 SSDP 发现请求"""
    # M-SEARCH 请求
    packet = b'M-SEARCH * HTTP/1.1\r\n'
    packet += b'HOST: 239.255.255.250:1900\r\n'
    packet += b'MAN: "ssdp:discover"\r\n'
    packet += b'ST: ssdp:all\r\n'
    packet += b'MX: 3\r\n'
    packet += b'\r\n'
    
    return packet


def _generate_coap_get():
    """生成 CoAP GET 请求"""
    # CoAP 头部
    version = 1
    type_field = 0  # Confirmable
    token_length = 0
    code = 1  # GET
    message_id = random.randint(0, 65535)
    
    header = (version << 6) | (type_field << 4) | token_length
    packet = struct.pack('!BBH', header, code, message_id)
    
    # URI-Path 选项: .well-known/core
    option_delta = 11  # URI-Path
    option_length = 0
    option_header = (option_delta << 4) | option_length
    packet += struct.pack('!B', option_header)
    
    return packet


def _generate_openvpn_handshake():
    """生成 OpenVPN 握手数据包"""
    # OpenVPN 数据包格式（简化）
    opcode_key_id = 0x01  # P_CONTROL_HARD_RESET_CLIENT_V2
    session_id = random.randint(0, 0xFFFFFFFF)
    packet_id = random.randint(0, 0xFFFFFFFF)
    
    packet = struct.pack('!BLL', opcode_key_id, session_id, packet_id)
    packet += b'\x00' * 8  # HMAC
    
    return packet


def _generate_radius_access_request():
    """生成 RADIUS Access-Request"""
    code = 1  # Access-Request
    identifier = random.randint(0, 255)
    length = 20  # 最小长度
    authenticator = b'\x00' * 16
    
    packet = struct.pack('!BBH', code, identifier, length)
    packet += authenticator
    
    return packet


def _generate_tacacs_authentication():
    """生成 TACACS+ 认证请求"""
    version = 0xC0  # TACACS+
    type_field = 1  # Authentication
    sequence = 1
    flags = 0
    session_id = random.randint(0, 0xFFFFFFFF)
    length = 0
    
    packet = struct.pack('!BBBBL', version, type_field, sequence, flags, session_id)
    packet += struct.pack('!L', length)
    
    return packet


def _generate_kerberos_udp():
    """生成 Kerberos UDP 请求"""
    # AS-REQ（简化版）
    pvno = 5  # Kerberos v5
    msg_type = 10  # AS-REQ
    
    # 简化的 Kerberos 数据包
    packet = struct.pack('!BB', pvno, msg_type)
    packet += b'\x00' * 20  # 简化的其他字段
    
    return packet


def _generate_iscsi_udp():
    """生成 iSCSI UDP 数据包"""
    # iSCSI 数据包（简化）
    opcode = 0x00  # NOP-Out
    flags = 0x80  # Final
    total_ahs_length = 0
    data_segment_length = 0
    lsn = 0
    itt = random.randint(0, 0xFFFFFFFF)
    ttt = 0xFFFFFFFF
    
    packet = struct.pack('!BBBBLLL', opcode, flags, total_ahs_length, 0,
                        data_segment_length, lsn, itt)
    packet += struct.pack('!L', ttt)
    
    return packet


def _generate_weave_net_udp():
    """生成 Weave Net UDP 探测包"""
    # Weave Net 使用自定义协议，通常以版本号开始
    # 简化的探测包：版本号 + 消息类型
    version = 1
    msg_type = 0x01  # 简化的消息类型
    packet = struct.pack('!BB', version, msg_type)
    # 添加一些填充数据
    packet += b'\x00' * 10
    return packet


def _generate_flannel_udp_backend():
    """生成 Flannel UDP backend 探测包"""
    # Flannel UDP backend 使用简单的封装格式
    # 通常包含 VNI (VXLAN Network Identifier) 和其他元数据
    vni = 1  # 默认 VNI
    reserved = 0
    # Flannel UDP 封装格式（简化）
    packet = struct.pack('!BBH', reserved, reserved, vni)
    # 添加一些填充数据
    packet += b'\x00' * 8
    return packet


def _generate_flannel_vxlan():
    """生成 Flannel VXLAN 探测包"""
    # VXLAN 头部格式（RFC 7348）
    # Flags (8 bits) + Reserved (24 bits) + VNI (24 bits) + Reserved (8 bits)
    flags = 0x08  # I flag set (valid VNI)
    reserved1 = 0
    vni = 1  # VXLAN Network Identifier
    reserved2 = 0
    
    # VXLAN 头部
    packet = struct.pack('!BBHBB', flags, 0, reserved1, vni, reserved2)
    # 添加一些填充数据（模拟内层以太网帧）
    packet += b'\x00' * 14  # 最小以太网帧大小的一部分
    return packet


def _stun_attr(attr_type, value):
    """构造STUN属性（参考turn_client.py的stun_attr函数）"""
    pad_len = (4 - (len(value) % 4)) % 4
    return struct.pack("!HH", attr_type, len(value)) + value + b"\x00" * pad_len


def _generate_stun_binding_request():
    """生成 STUN Binding Request 消息（RFC 5389）
    参考turn_client.py的build_msg函数（无认证情况）
    """
    STUN_BINDING_REQUEST = 0x0001
    STUN_MAGIC_COOKIE = 0x2112A442
    
    # 生成随机事务ID（参考gen_tid函数）
    tid = os.urandom(12)
    
    # 无属性
    attrs = []
    body = b"".join(attrs)
    
    # 构建STUN消息（参考build_msg的无认证分支）
    msg = struct.pack("!HHI12s", STUN_BINDING_REQUEST, len(body), STUN_MAGIC_COOKIE, tid) + body
    
    return msg


def _generate_stun_binding_request_fingerprint():
    """生成带Fingerprint属性的STUN Binding Request消息（RFC 5389）
    参考turn_client.py的build_msg函数（无认证但带Fingerprint的情况）
    """
    STUN_BINDING_REQUEST = 0x0001
    STUN_MAGIC_COOKIE = 0x2112A442
    STUN_ATTR_FINGERPRINT = 0x8028
    
    # 生成随机事务ID
    tid = os.urandom(12)
    
    # 无其他属性，只有FINGERPRINT
    attrs = []
    body = b"".join(attrs)
    
    # 添加FINGERPRINT占位符
    fp_attr_placeholder = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, 0)
    body_with_fp_placeholder = body + fp_attr_placeholder
    
    # 构建消息头（包含FINGERPRINT占位符的长度）
    header = struct.pack("!HHI12s", STUN_BINDING_REQUEST, len(body_with_fp_placeholder), STUN_MAGIC_COOKIE, tid)
    
    # 计算FINGERPRINT（CRC32，XOR 0x5354554e）
    # 注意：FINGERPRINT的计算基于header + body（不包含FINGERPRINT本身）
    msg_for_crc = header + body
    crc32_val = zlib.crc32(msg_for_crc) & 0xffffffff
    fingerprint_val = crc32_val ^ 0x5354554e
    
    # 替换占位符FINGERPRINT为真实值
    fp_attr = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, fingerprint_val)
    
    # 重新构建消息
    body_with_fp = body + fp_attr
    header = struct.pack("!HHI12s", STUN_BINDING_REQUEST, len(body_with_fp), STUN_MAGIC_COOKIE, tid)
    msg = header + body_with_fp
    
    return msg


def _generate_turn_allocate_request():
    """生成 TURN Allocate Request 消息（RFC 8656）
    参考turn_client.py的build_msg函数（无认证但带Fingerprint的情况）
    """
    STUN_ALLOCATE_REQUEST = 0x0003
    STUN_MAGIC_COOKIE = 0x2112A442
    STUN_ATTR_REQUESTED_TRANSPORT = 0x0019
    STUN_ATTR_FINGERPRINT = 0x8028
    
    # 生成随机事务ID
    tid = os.urandom(12)
    
    # REQUESTED-TRANSPORT 属性：请求UDP传输（协议号17）
    transport_protocol = 17  # UDP
    # 使用stun_attr函数构造属性（需要4字节对齐）
    requested_transport_value = struct.pack("!BBBB", transport_protocol, 0, 0, 0)
    requested_transport_attr = _stun_attr(STUN_ATTR_REQUESTED_TRANSPORT, requested_transport_value)
    
    # 构建属性列表
    attrs = [requested_transport_attr]
    body = b"".join(attrs)
    
    # 添加FINGERPRINT占位符
    fp_attr_placeholder = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, 0)
    body_with_fp_placeholder = body + fp_attr_placeholder
    
    # 构建消息头（包含FINGERPRINT占位符的长度）
    header = struct.pack("!HHI12s", STUN_ALLOCATE_REQUEST, len(body_with_fp_placeholder), STUN_MAGIC_COOKIE, tid)
    
    # 计算FINGERPRINT（CRC32，XOR 0x5354554e）
    # 注意：FINGERPRINT的计算基于header + body（不包含FINGERPRINT本身）
    msg_for_crc = header + body
    crc32_val = zlib.crc32(msg_for_crc) & 0xffffffff
    fingerprint_val = crc32_val ^ 0x5354554e
    
    # 替换占位符FINGERPRINT为真实值
    fp_attr = struct.pack("!HHI", STUN_ATTR_FINGERPRINT, 4, fingerprint_val)
    
    # 重新构建消息
    body_with_fp = body + fp_attr
    header = struct.pack("!HHI12s", STUN_ALLOCATE_REQUEST, len(body_with_fp), STUN_MAGIC_COOKIE, tid)
    msg = header + body_with_fp
    
    return msg


def get_protocol_packet(protocol_name):
    """
    获取指定协议的数据包
    
    Args:
        protocol_name: 协议名称（UDP_PROTOCOL_PACKETS 字典的键）
    
    Returns:
        bytes: 协议数据包，如果协议不存在则返回 None
    """
    if protocol_name not in UDP_PROTOCOL_PACKETS:
        return None
    
    protocol_info = UDP_PROTOCOL_PACKETS[protocol_name]
    
    # 如果数据包是动态生成的，调用 generate 函数
    if protocol_info.get('generate'):
        return protocol_info['generate']()
    else:
        return protocol_info.get('packet')


def get_all_protocols():
    """获取所有可用的协议名称列表"""
    return list(UDP_PROTOCOL_PACKETS.keys())


def get_protocols_for_port(port):
    """
    根据端口号获取可能的协议列表
    
    Args:
        port: 端口号
    
    Returns:
        list: 协议名称列表
    """
    protocols = []
    for name, info in UDP_PROTOCOL_PACKETS.items():
        if info.get('default_port') == port:
            protocols.append(name)
    return protocols

