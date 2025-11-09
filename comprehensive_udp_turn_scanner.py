#!/usr/bin/env python3
"""
Comprehensive UDP TURN Scanner

1. 测试指定 TURN 服务器是否支持 UDP 或 TCP+UDP (RFC 6062) 能力。
2. 根据能力选择合适的分配模式。
3. 复用 turn_udp_port_scanner 中的 ICMP 解析逻辑，对内网目标进行批量 UDP 端口扫描。

支持通过文件或命令行参数提供待测 IP 与端口列表，扫描结果可输出为 JSON。
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TURN_UTILS_DIR = os.path.join(CURRENT_DIR, "turn_utils")

for path in (TURN_UTILS_DIR, CURRENT_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from turn_utils.turn_client import (
    resolve_server_address,
    create_permission,
    channel_bind,
    channel_data,
    channel_data_tcp,
    parse_attrs,
    STUN_MAGIC_COOKIE,
    STUN_ATTR_XOR_PEER_ADDRESS,
)
from turn_utils.test_turn_capabilities import (
    test_udp_turn,
    test_tcp_udp_turn,
    allocate_with_fallback,
    allocate_tcp_udp_with_fallback,
)
from turn_utils.turn_udp_port_scanner import (
    STUN_DATA_INDICATION,
    STUN_ATTR_ICMP,
    ICMP_DEST_UNREACH,
    ICMP_PORT_UNREACH,
)
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT


def load_targets_from_file(file_path: str, default: List[str]) -> List[str]:
    if not file_path:
        return default
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    except FileNotFoundError:
        print(f"[!] 指定的文件 {file_path} 未找到，使用默认列表")
    return default


def parse_targets(targets: Optional[str], default_file: Optional[str], default: List[str]) -> List[str]:
    if targets:
        return [item.strip() for item in targets.split(",") if item.strip()]
    return load_targets_from_file(default_file, default)


def parse_ports(port_spec: Optional[str], ports_file: Optional[str], default: List[int]) -> List[int]:
    if port_spec:
        ports: List[int] = []
        for part in port_spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start, end = map(int, part.split("-", maxsplit=1))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))
    if ports_file:
        try:
            with open(ports_file, "r", encoding="utf-8") as f:
                values: List[int] = []
                for line in f:
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue
                    if "-" in text:
                        start, end = map(int, text.split("-", maxsplit=1))
                        values.extend(range(start, end + 1))
                    else:
                        values.append(int(text))
                if values:
                    return sorted(set(values))
        except FileNotFoundError:
            print(f"[!] 指定的端口文件 {ports_file} 未找到，使用默认端口列表")
    return sorted({int(p) for p in default})


def receive_icmp_generic(sock, is_stream: bool, timeout: float) -> Tuple[Optional[int], Optional[int], Optional[Tuple[str, int]]]:
    """从 TURN 连接接收 ICMP 信息，兼容 UDP 与 TCP 控制通道。"""
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            if is_stream:
                data = sock.recv(4096)
            else:
                data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception as exc:
            print(f"[-] 接收 ICMP 错误时发生异常: {exc}")
            return (None, None, None)

        if not data:
            continue

        # 针对 TCP，可能需要补齐剩余的 STUN 消息体
        if is_stream and len(data) >= 4 and data[0] & 0xC0 == 0x00:
            msg_len = struct.unpack("!H", data[2:4])[0] + 20
            while len(data) < msg_len:
                chunk = sock.recv(msg_len - len(data))
                if not chunk:
                    break
                data += chunk

        try:
            msg_type, tid, attrs = parse_attrs(data)
        except Exception as exc:
            print(f"[!] 无法解析收到的数据: {exc}, size={len(data)}")
            continue

        if msg_type == STUN_DATA_INDICATION:
            icmp_attr = attrs.get(STUN_ATTR_ICMP)
            xor_peer_attr = attrs.get(STUN_ATTR_XOR_PEER_ADDRESS)
            if icmp_attr and xor_peer_attr and len(icmp_attr) >= 4 and len(xor_peer_attr) >= 8:
                icmp_type = icmp_attr[2]
                icmp_code = icmp_attr[3]

                family = xor_peer_attr[1]
                if family == 1:  # IPv4
                    xor_port = struct.unpack("!H", xor_peer_attr[2:4])[0]
                    xor_ip = xor_peer_attr[4:8]
                    peer_port = xor_port ^ (STUN_MAGIC_COOKIE >> 16)
                    peer_ip = socket.inet_ntoa(
                        bytes(
                            xor_ip[i] ^ ((STUN_MAGIC_COOKIE >> (8 * (3 - i))) & 0xFF)
                            for i in range(4)
                        )
                    )
                    print(f"[+] Received ICMP error: type={icmp_type}, code={icmp_code}, peer={peer_ip}:{peer_port}")
                    return (icmp_type, icmp_code, (peer_ip, peer_port))

            print("[+] Received Data indication (no ICMP attribute)")
        else:
            error_code = attrs.get(9)
            if error_code:
                error_class = error_code[2] if len(error_code) > 2 else 0
                error_number = error_code[3] if len(error_code) > 3 else 0
                reason = error_code[4:].decode("utf-8", errors="ignore") if len(error_code) > 4 else ""
                print(f"[!] Received error response: {error_class}{error_number:02d} {reason}")
                if error_class == 4 and error_number == 1:
                    print("[!] 401 error ignored (indications should be unauthenticated)")
                    continue

    return (None, None, None)


def scan_udp_port_udp_mode(
    server_address: Tuple[str, int],
    turn_server: str,
    turn_port: int,
    username: str,
    password: str,
    realm: Optional[str],
    target_ip: str,
    target_port: int,
    timeout: float,
) -> str:
    from turn_utils.turn_udp_port_scanner import scan_udp_port

    return scan_udp_port(
        turn_server,
        turn_port,
        username,
        password,
        realm,
        target_ip,
        target_port,
        timeout=int(timeout),
    )


def scan_udp_port_tcp_udp_mode(
    server_address: Tuple[str, int],
    turn_server: str,
    turn_port: int,
    username: str,
    password: str,
    realm: Optional[str],
    use_tls: bool,
    target_ip: str,
    target_port: int,
    timeout: float,
) -> str:
    result = allocate_tcp_udp_with_fallback(
        server_address,
        username,
        password,
        realm,
        turn_server,
        use_tls,
    )
    if not result[0]:
        print("[-] Failed to allocate TCP+UDP TURN relay")
        return "error"

    control_sock, nonce, realm_ret, integrity_key, actual_server_address, *extra = result[0]
    mi_algorithm = extra[0] if extra else None
    is_short_term = result[1]
    print(f"[+] TCP+UDP TURN allocation successful ({'short-term' if is_short_term else 'long-term'})")
    try:
        if not create_permission(
            control_sock,
            nonce,
            realm_ret,
            integrity_key,
            target_ip,
            target_port,
            actual_server_address,
            username,
            mi_algorithm,
        ):
            print("[-] Failed to create permission")
            return "error"

        channel_number = random.randint(0x4000, 0x4FFF)
        if not channel_bind(
            control_sock,
            nonce,
            realm_ret,
            integrity_key,
            target_ip,
            target_port,
            channel_number,
            actual_server_address,
            username,
            mi_algorithm,
        ):
            print("[-] Failed to bind channel")
            return "error"

        if not channel_data_tcp(control_sock, channel_number, b"", actual_server_address):
            return "error"

        icmp_type, icmp_code, _ = receive_icmp_generic(control_sock, True, timeout)
        if icmp_type == ICMP_DEST_UNREACH and icmp_code == ICMP_PORT_UNREACH:
            return "closed"
        elif icmp_type is not None:
            return "filtered"
        return "open|filtered"
    finally:
        try:
            control_sock.close()
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Comprehensive UDP TURN Scanner")
    parser.add_argument("--turn-server", default=DEFAULT_TURN_SERVER, help="TURN 服务器地址")
    parser.add_argument("--turn-port", type=int, default=DEFAULT_TURN_PORT, help="TURN 服务器端口")
    parser.add_argument("--username", required=True, help="TURN 用户名")
    parser.add_argument("--password", required=True, help="TURN 密码")
    parser.add_argument("--realm", help="TURN 认证域")
    parser.add_argument("--tls", action="store_true", help="与 TURN 服务器建立 TLS 连接（用于 tcp-udp 模式）")
    parser.add_argument("--targets", help="逗号分隔的目标 IP 列表")
    parser.add_argument("--targets-file", help="目标 IP 文件（默认: standard_test_ips.txt）")
    parser.add_argument("--ports", help="端口列表或范围（如 53,123 或 1000-1010）")
    parser.add_argument("--ports-file", help="端口文件（默认: standard_test_ports.txt）")
    parser.add_argument("--timeout", type=int, default=5, help="等待响应的超时时间（秒）")
    parser.add_argument("--output", help="将结果保存为 JSON 文件")
    parser.add_argument("--cap-target", default="8.8.8.8", help="能力测试目标 IP (默认: 8.8.8.8)")
    parser.add_argument("--cap-port", type=int, default=53, help="能力测试目标端口 (默认: 53)")

    args = parser.parse_args()

    server_address = resolve_server_address(args.turn_server, args.turn_port)
    if not server_address:
        print("[-] 无法解析 TURN 服务器地址")
        return 1

    print("=== TURN Capability Test ===")
    udp_capable = test_udp_turn(
        server_address,
        args.username,
        args.password,
        args.realm,
        args.turn_server,
        target_ip=args.cap_target,
        target_port=args.cap_port,
    )
    tcp_udp_capable = test_tcp_udp_turn(
        server_address,
        args.username,
        args.password,
        args.realm,
        args.turn_server,
        args.tls,
        target_ip=args.cap_target,
        target_port=args.cap_port,
    )

    if udp_capable:
        mode = "udp"
        print("[+] 使用 UDP TURN 模式进行扫描")
    elif tcp_udp_capable:
        mode = "tcp_udp"
        print("[+] 使用 TCP+UDP TURN 模式进行扫描")
    else:
        print("[-] TURN 服务器不支持 UDP 或 TCP+UDP 模式，无法继续扫描")
        return 1

    targets = parse_targets(args.targets, args.targets_file, load_targets_from_file("standard_test_ips.txt", []))
    if not targets:
        print("[-] 未找到任何目标 IP")
        return 1

    ports = parse_ports(args.ports, args.ports_file, load_targets_from_file("standard_test_ports.txt", [53, 123]))
    if not ports:
        print("[-] 未找到任何端口")
        return 1

    results: Dict[str, Dict[int, str]] = {}
    for target_ip in targets:
        print(f"\n=== Scanning target {target_ip} ===")
        per_port: Dict[int, str] = {}
        for port in ports:
            print(f"\n--- Scanning {target_ip}:{port} ---")
            if mode == "udp":
                status = scan_udp_port_udp_mode(
                    server_address,
                    args.turn_server,
                    args.turn_port,
                    args.username,
                    args.password,
                    args.realm,
                    target_ip,
                    port,
                    args.timeout,
                )
            else:
                status = scan_udp_port_tcp_udp_mode(
                    server_address,
                    args.turn_server,
                    args.turn_port,
                    args.username,
                    args.password,
                    args.realm,
                    args.tls,
                    target_ip,
                    port,
                    args.timeout,
                )
            per_port[port] = status
            time.sleep(0.3)
        results[target_ip] = per_port

    print("\n=== 扫描汇总 ===")
    for ip, port_map in results.items():
        print(f"\n目标 {ip}:")
        for port, status in sorted(port_map.items()):
            print(f"  {port:5d}: {status}")

    if args.output:
        try:
            output_obj = {
                "turn_server": {
                    "host": args.turn_server,
                    "port": args.turn_port,
                    "mode": mode,
                    "tls": args.tls,
                },
                "targets": results,
            }
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(output_obj, f, indent=2)
            print(f"[+] 结果已保存到 {args.output}")
        except Exception as exc:
            print(f"[-] 保存结果失败: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

