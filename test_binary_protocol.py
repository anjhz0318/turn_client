#!/usr/bin/env python3
"""
简单的二进制协议测试脚本，通过TURN转发
支持SOCKS5和Redis等协议
"""

import socket
import sys
import argparse
from turn_utils import (
    allocate_tcp, tcp_connection_bind, tcp_send_data, tcp_receive_data,
    resolve_server_address, resolve_peer_address, tcp_connect
)

def test_protocol(turn_server, turn_port, username, password, realm, use_tls,
                 target_host, target_port, data_to_send, protocol_name="Unknown"):
    """测试二进制协议"""
    print(f"=== Testing {protocol_name} protocol ===")
    print(f"Target: {target_host}:{target_port}")
    print(f"Data to send: {len(data_to_send)} bytes")
    print(f"Data (hex): {' '.join(f'{b:02x}' for b in data_to_send[:20])}{'...' if len(data_to_send) > 20 else ''}")
    
    control_sock = None
    data_sock = None
    
    try:
        # 1. 分配TCP TURN中继地址
        server_address = resolve_server_address(turn_server, turn_port)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return False
        
        print(f"[+] Connecting to TURN server: {server_address}")
        result = allocate_tcp(server_address, username, password, realm, use_tls)
        if not result:
            print("[-] Failed to allocate TCP TURN relay")
            return False
        
        control_sock, nonce, realm, integrity_key, actual_server_address = result
        print("[+] TCP TURN allocation successful")
        
        # 2. 发起TCP连接到对等方
        peer_ip = resolve_peer_address(target_host)
        if not peer_ip:
            print(f"[-] Failed to resolve peer {target_host}")
            return False
        
        print(f"[+] Initiating TCP connection to {target_host}:{target_port}")
        connection_id = tcp_connect(control_sock, nonce, realm, integrity_key, 
                                   peer_ip, target_port, username)
        if not connection_id:
            print("[-] Failed to initiate TCP connection")
            return False
        
        print(f"[+] Got connection ID: {connection_id}")
        
        # 3. 建立数据连接
        data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_sock.settimeout(30)
        data_sock.connect(actual_server_address)
        print("[+] Data connection established")
        
        # 4. 绑定数据连接到对等方连接
        if not tcp_connection_bind(data_sock, nonce, realm, integrity_key, 
                                   connection_id, actual_server_address, username):
            print("[-] Failed to bind data connection")
            return False
        
        print("[+] Data connection bound successfully")
        
        # 5. 发送数据
        print(f"[+] Sending {protocol_name} request...")
        if not tcp_send_data(data_sock, data_to_send):
            print("[-] Failed to send data")
            return False
        
        print("[+] Data sent successfully")
        print("[+] Waiting for response...")
        
        # 6. 接收响应
        data_sock.settimeout(10)
        try:
            response = tcp_receive_data(data_sock)
            if response:
                print(f"[+] Received {len(response)} bytes:")
                # 尝试以文本显示，否则显示十六进制
                try:
                    text = response.decode('utf-8', errors='replace')
                    if all(ord(c) >= 32 or c in '\r\n\t' for c in text):
                        print("=" * 60)
                        print(text)
                        print("=" * 60)
                    else:
                        print("=" * 60)
                        print(' '.join(f'{b:02x}' for b in response[:100]))
                        if len(response) > 100:
                            print(f"... (total {len(response)} bytes)")
                        print("=" * 60)
                except:
                    print("=" * 60)
                    print(' '.join(f'{b:02x}' for b in response[:100]))
                    if len(response) > 100:
                        print(f"... (total {len(response)} bytes)")
                    print("=" * 60)
                return True
            else:
                print("[-] No response received")
                return False
        except socket.timeout:
            print("[-] Timeout waiting for response")
            return False
        except Exception as e:
            print(f"[-] Error receiving response: {e}")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        if data_sock:
            data_sock.close()
        if control_sock:
            control_sock.close()

def main():
    parser = argparse.ArgumentParser(description="简单的二进制协议测试脚本，通过TURN转发")
    parser.add_argument("protocol", choices=["socks5", "redis", "rtsp", "probe", "raw", "tlshello"], help="协议/模式")
    parser.add_argument("--host", dest="host", default="192.168.0.1", help="目标主机")
    parser.add_argument("--port", dest="port", type=int, default=8888, help="目标端口")
    parser.add_argument("--data-hex", dest="data_hex", default=None, help="raw模式发送的十六进制数据，如: 0d0a")
    parser.add_argument("--sni", dest="sni", default=None, help="tlshello模式的SNI主机名")
    parser.add_argument("--alpn", dest="alpn", default="h2,http/1.1", help="tlshello模式的ALPN，逗号分隔；留空禁用")
    # TURN配置（按需可改为参数，这里保持内置）
    parser.add_argument("--turn-server", dest="turn_server", default="43.128.254.169")
    parser.add_argument("--turn-port", dest="turn_port", type=int, default=443)
    parser.add_argument("--username", dest="username", default="1761748318:turnuserid_35661")
    parser.add_argument("--password", dest="password", default="K3Xq6HmhzrKstDq3YM1NiJwixG4=")
    parser.add_argument("--realm", dest="realm", default=None)
    parser.add_argument("--tls", dest="use_tls", action="store_true", default=True, help="与TURN的TLS")

    args = parser.parse_args()

    protocol = args.protocol
    turn_server = args.turn_server
    turn_port = args.turn_port
    username = args.username
    password = args.password
    realm = args.realm
    use_tls = args.use_tls

    target_host = args.host
    target_port = args.port

    def build_tls_client_hello(sni: str | None, alpn_csv: str | None) -> bytes:
        import os
        import struct
        client_version = b"\x03\x03"  # TLS 1.2
        random_bytes = os.urandom(32)
        session_id = b""  # empty
        # 常见、安全性较好的套件（含 ECDHE + AESGCM/CHACHA20），以及若干回退
        cipher_suites = [
            0x1301, 0x1302, 0x1303,            # TLS 1.3 (多数实现会忽略于1.2，但保留便于指纹)
            0xC02F, 0xC02B,                    # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 / _AES_256_GCM_SHA384
            0xC02C, 0xC030,                    # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 / _AES_256_GCM_SHA384
            0xCCA8, 0xCCA9,                    # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 / ECDSA 同款
            0x009C, 0x009D,                    # TLS_RSA_WITH_AES_128_GCM_SHA256 / _AES_256_GCM_SHA384
            0x002F, 0x0035                     # TLS_RSA_WITH_AES_128_CBC_SHA / _AES_256_CBC_SHA（回退）
        ]
        cs_bytes = b"".join(struct.pack(">H", cs) for cs in cipher_suites)
        comp_methods = b"\x00"  # null only

        # Extensions
        exts = []

        # SNI
        if sni:
            host_bytes = sni.encode("ascii", errors="ignore")
            name = struct.pack(">B H", 0, len(host_bytes)) + host_bytes  # type=0(hostname)
            sni_list = struct.pack(">H", len(name)) + name
            sni_ext = struct.pack(">H H H", 0x0000, len(sni_list) + 2, len(sni_list)) + sni_list
            exts.append(sni_ext)

        # Supported Groups (elliptic curves)
        groups = [23, 24, 25, 29, 30]  # secp256r1, secp384r1, secp521r1, x25519, x448
        groups_bytes = b"".join(struct.pack(">H", g) for g in groups)
        sg_body = struct.pack(">H", len(groups_bytes)) + groups_bytes
        sg_ext = struct.pack(">H H", 0x000a, len(sg_body)) + sg_body
        exts.append(sg_ext)

        # EC Point Formats
        epf_body = b"\x01\x00"  # length=1, uncompressed(0)
        epf_ext = struct.pack(">H H", 0x000b, len(epf_body)) + epf_body
        exts.append(epf_ext)

        # Signature Algorithms
        sig_algs = [
            0x0804, 0x0805, 0x0806,  # rsa_pss_rsae_sha256/384/512
            0x0401, 0x0501, 0x0601,  # rsa_pkcs1_sha256/384/512
            0x0403, 0x0503, 0x0603,  # ecdsa_secp256r1_sha256 / 384 / 521
        ]
        sig_bytes = b"".join(struct.pack(">H", s) for s in sig_algs)
        sa_body = struct.pack(">H", len(sig_bytes)) + sig_bytes
        sa_ext = struct.pack(">H H", 0x000d, len(sa_body)) + sa_body
        exts.append(sa_ext)

        # ALPN
        if alpn_csv is not None and alpn_csv != "":
            protos = [p.strip() for p in alpn_csv.split(",") if p.strip()]
            alpn_proto_bytes = b"".join(bytes([len(p)]) + p.encode("ascii", errors="ignore") for p in protos)
            alpn_body = struct.pack(">H", len(alpn_proto_bytes) + 2) + struct.pack(">H", len(alpn_proto_bytes)) + alpn_proto_bytes
            alpn_ext = struct.pack(">H H", 0x0010, len(alpn_body)) + alpn_body
            exts.append(alpn_ext)

        # Extended Master Secret（兼容性）
        ems_ext = struct.pack(">H H", 0x0017, 0)
        exts.append(ems_ext)

        # SessionTicket（空，仅表明支持）
        st_ext = struct.pack(">H H", 0x0023, 0)
        exts.append(st_ext)

        extensions = b"".join(exts)
        ch_body = (
            client_version +
            random_bytes +
            bytes([len(session_id)]) + session_id +
            struct.pack(">H", len(cs_bytes)) + cs_bytes +
            bytes([len(comp_methods)]) + comp_methods +
            struct.pack(">H", len(extensions)) + extensions
        )

        # Handshake: ClientHello
        hs = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
        # TLS record
        record = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
        return record

    if protocol == "socks5":
        data = bytes([0x05, 0x01, 0x00])
        test_protocol(turn_server, turn_port, username, password, realm, use_tls,
                     target_host, target_port, data, "SOCKS5")

    elif protocol == "redis":
        data = b"PING\r\n"
        test_protocol(turn_server, turn_port, username, password, realm, use_tls,
                     target_host, target_port, data, "Redis")

    elif protocol == "rtsp":
        data = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        test_protocol(turn_server, turn_port, username, password, realm, use_tls,
                     target_host, target_port, data, "RTSP")

    elif protocol == "probe":
        # 轻量探测：发送CRLF，观察是否有banner/错误返回
        data = b"\r\n"
        test_protocol(turn_server, turn_port, username, password, realm, use_tls,
                     target_host, target_port, data, "Probe")

    elif protocol == "raw":
        if not args.data_hex:
            print("[-] raw 模式需要 --data-hex，例如 --data-hex 0d0a")
            return 1
        try:
            data = bytes.fromhex(args.data_hex)
        except Exception as e:
            print(f"[-] 解析 data-hex 失败: {e}")
            return 1
        test_protocol(turn_server, turn_port, username, password, realm, use_tls,
                     target_host, target_port, data, "Raw")

    elif protocol == "tlshello":
        data = build_tls_client_hello(args.sni, args.alpn)
        label = "TLS ClientHello"
        if args.sni:
            label += f" (SNI={args.sni})"
        if args.alpn:
            label += f" (ALPN={args.alpn})"
        test_protocol(turn_server, turn_port, username, password, realm, use_tls,
                     target_host, target_port, data, label)

    else:
        print(f"[-] Unknown protocol: {protocol}")
        print("Supported: socks5, redis, rtsp, probe, raw, tlshello")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())

