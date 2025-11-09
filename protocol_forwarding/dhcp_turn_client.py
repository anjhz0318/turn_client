#!/usr/bin/env python3
"""
DHCP Client via UDP TURN
通过 TURN 中继发送 DHCP Discover / Request 报文并解析响应。
"""

import argparse
import os
import random
import socket
import struct
import sys
import time
from typing import Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
TURN_UTILS_DIR = os.path.join(PROJECT_ROOT, "turn_utils")

for path in (PROJECT_ROOT, TURN_UTILS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from turn_utils import (
    create_permission,
    channel_bind,
    channel_data,
    channel_data_tcp,
    resolve_server_address,
)
from test_turn_capabilities import allocate_with_fallback, allocate_tcp_udp_with_fallback
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT


DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"


def generate_mac() -> bytes:
    """生成一个本地管理的MAC地址。"""
    mac = [0x02, 0x00, 0x00, random.randint(0x00, 0x7F), random.randint(0x00, 0xFF), random.randint(0x00, 0xFF)]
    return bytes(mac)


class DHCPTURNClient:
    """通过 TURN 中继与 DHCP 服务器通信的客户端。"""

    def __init__(
        self,
        target_ip: str,
        target_port: int = 67,
        client_port: int = 68,
        turn_server: Optional[str] = None,
        turn_port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        realm: Optional[str] = None,
        use_tcp_udp: bool = False,
        use_tls: bool = False,
        mac_address: Optional[str] = None,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.client_port = client_port
        self.turn_server = turn_server
        self.turn_port = turn_port
        self.username = username
        self.password = password
        self.auth_realm = realm
        self.use_tcp_udp = use_tcp_udp
        self.use_tls = use_tls
        self.mac = self._parse_mac(mac_address) if mac_address else generate_mac()

        self.sock = None
        self.nonce = None
        self.realm = None
        self.integrity_key = None
        self.actual_server_address = None
        self.channel_number = 0x4001
        self.mi_algorithm = None
        self.is_short_term = None
        self.last_xid = None

    @staticmethod
    def _parse_mac(mac_str: str) -> bytes:
        parts = mac_str.split(":")
        if len(parts) != 6:
            raise ValueError("MAC 地址格式应为 xx:xx:xx:xx:xx:xx")
        return bytes(int(part, 16) for part in parts)

    def connect(self) -> bool:
        """建立 TURN 中继连接。"""
        print(f"[+] Connecting to DHCP server {self.target_ip}:{self.target_port} via TURN")

        server_address = resolve_server_address(
            self.turn_server or DEFAULT_TURN_SERVER,
            self.turn_port or DEFAULT_TURN_PORT,
        )
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return False

        print(f"[+] Using TURN server: {server_address}")

        if self.use_tcp_udp:
            result, is_short_term = allocate_tcp_udp_with_fallback(
                server_address,
                self.username,
                self.password,
                self.auth_realm,
                self.turn_server,
                self.use_tls,
            )
        else:
            result, is_short_term = allocate_with_fallback(
                server_address,
                self.username,
                self.password,
                self.auth_realm,
                self.turn_server,
            )

        if not result:
            print("[-] Failed to allocate TURN relay")
            return False

        self.sock, self.nonce, self.realm, self.integrity_key, self.actual_server_address, *extra = result
        self.mi_algorithm = extra[0] if extra else None
        self.is_short_term = is_short_term

        cred_type = "short-term" if self.is_short_term else "long-term"
        print(f"[+] TURN allocation successful ({cred_type} credential)")
        print(f"[+] Relay address: {self.actual_server_address}")

        if not create_permission(
            self.sock,
            self.nonce,
            self.realm,
            self.integrity_key,
            self.target_ip,
            self.target_port,
            self.actual_server_address,
            self.username,
            self.mi_algorithm,
        ):
            print("[-] Failed to create permission")
            self.sock.close()
            return False

        if not channel_bind(
            self.sock,
            self.nonce,
            self.realm,
            self.integrity_key,
            self.target_ip,
            self.target_port,
            self.channel_number,
            self.actual_server_address,
            self.username,
            self.mi_algorithm,
        ):
            print("[-] Failed to bind channel")
            self.sock.close()
            return False

        print(f"[+] Channel {self.channel_number} bound successfully")
        return True

    def build_discover(self) -> bytes:
        """构造 DHCP Discover 报文。"""
        xid = random.getrandbits(32)
        self.last_xid = xid

        op = 1  # 请求
        htype = 1  # Ethernet
        hlen = 6
        hops = 0
        secs = 0
        flags = 0x8000  # 广播标志

        ciaddr = yiaddr = siaddr = giaddr = b"\x00\x00\x00\x00"
        chaddr = self.mac + b"\x00" * (16 - len(self.mac))
        sname = b"\x00" * 64
        boot_file = b"\x00" * 128

        options = bytearray()
        options += DHCP_MAGIC_COOKIE
        # DHCP Message Type: Discover
        options += b"\x35\x01\x01"
        # Client identifier (type 1 + MAC)
        options += b"\x3d\x07\x01" + self.mac
        # Parameter Request List
        options += b"\x37\x05\x01\x03\x06\x0f\x2a"
        # Host Name
        hostname = f"turn-dhcp-{self.mac.hex()[:6]}".encode()
        options += bytes([12, len(hostname)]) + hostname
        # Requested IP Address placeholder (optional)
        options += b"\x32\x04\x00\x00\x00\x00"
        # End option
        options += b"\xff"
        # Pad to multiple of 4 bytes
        if len(options) % 4:
            options += b"\x00" * (4 - (len(options) % 4))

        header = struct.pack(
            "!BBBBIHHIIII16s64s128s",
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            int.from_bytes(ciaddr, "big"),
            int.from_bytes(yiaddr, "big"),
            int.from_bytes(siaddr, "big"),
            int.from_bytes(giaddr, "big"),
            chaddr,
            sname,
            boot_file,
        )

        return header + bytes(options)

    def send_discover(self) -> bool:
        """发送 DHCP Discover 请求。"""
        packet = self.build_discover()
        print(f"[+] Sending DHCP Discover (XID=0x{self.last_xid:08x}, MAC={self.mac.hex(':')})")

        sender = channel_data_tcp if self.use_tcp_udp else channel_data
        if not sender(self.sock, self.channel_number, packet, self.actual_server_address):
            print("[-] Failed to send DHCP Discover")
            return False
        print("[+] DHCP Discover sent")
        return True

    def receive_response(self, timeout: int = 10) -> Optional[dict]:
        """接收 DHCP 报文并解析。"""
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                self.sock.settimeout(remaining)
                if self.use_tcp_udp:
                    data = self.sock.recv(2048)
                else:
                    data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except Exception as exc:
                print(f"[-] Error receiving data: {exc}")
                return None

            if len(data) < 4:
                continue

            channel_number = struct.unpack("!H", data[:2])[0]
            data_length = struct.unpack("!H", data[2:4])[0]
            if channel_number != self.channel_number or len(data) < 4 + data_length:
                continue

            payload = data[4:4 + data_length]
            if len(payload) < 240:
                continue

            return self.parse_dhcp(payload)

        print("[+] No DHCP response received within timeout")
        return None

    def parse_dhcp(self, payload: bytes) -> Optional[dict]:
        """解析 DHCP 报文。"""
        (
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
        ) = struct.unpack("!BBBBIHHIIII", payload[:28])

        chaddr = payload[28:44][:hlen]
        options_start = 240  # 236 bytes header + 4 bytes magic cookie
        if payload[236:240] != DHCP_MAGIC_COOKIE:
            print("[-] Invalid DHCP magic cookie")
            return None

        options = payload[options_start:]
        parsed_options = {}
        idx = 0
        while idx < len(options):
            code = options[idx]
            if code == 255:
                break
            if code == 0:
                idx += 1
                continue
            if idx + 1 >= len(options):
                break
            length = options[idx + 1]
            value = options[idx + 2: idx + 2 + length]
            parsed_options[code] = value
            idx += 2 + length

        msg_type = parsed_options.get(53, b"\x00")
        human = {
            1: "Discover",
            2: "Offer",
            3: "Request",
            5: "Ack",
            6: "Nak",
        }.get(msg_type[0], f"Unknown({msg_type[0]})")

        result = {
            "op": op,
            "xid": xid,
            "client_mac": ":".join(f"{b:02x}" for b in chaddr),
            "yiaddr": socket.inet_ntoa(yiaddr.to_bytes(4, "big")),
            "siaddr": socket.inet_ntoa(siaddr.to_bytes(4, "big")),
            "giaddr": socket.inet_ntoa(giaddr.to_bytes(4, "big")),
            "msg_type": msg_type[0] if msg_type else None,
            "msg_type_human": human,
            "options": parsed_options,
        }

        print(f"[+] Received DHCP message type: {human}, XID=0x{xid:08x}")
        print(f"    Offered IP: {result['yiaddr']}")
        if 54 in parsed_options:
            print(f"    DHCP Server ID: {socket.inet_ntoa(parsed_options[54])}")
        if 51 in parsed_options:
            lease = int.from_bytes(parsed_options[51], "big")
            print(f"    Lease Time: {lease} seconds")
        if 1 in parsed_options:
            print(f"    Subnet Mask: {socket.inet_ntoa(parsed_options[1])}")
        if 3 in parsed_options:
            print(f"    Router: {socket.inet_ntoa(parsed_options[3])}")
        if 6 in parsed_options:
            dns_servers = [
                socket.inet_ntoa(parsed_options[6][i:i + 4])
                for i in range(0, len(parsed_options[6]), 4)
            ]
            print(f"    DNS Servers: {', '.join(dns_servers)}")

        return result

    def disconnect(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        print("[+] Disconnected")


def main() -> int:
    parser = argparse.ArgumentParser(description="DHCP Client via UDP TURN")
    parser.add_argument("--target-ip", required=True, help="DHCP 服务器 IP 地址")
    parser.add_argument("--target-port", type=int, default=67, help="DHCP 服务器端口 (默认: 67)")
    parser.add_argument("--client-port", type=int, default=68, help="客户端期望端口 (仅显示用途)")
    parser.add_argument("--turn-server", help="TURN 服务器地址")
    parser.add_argument("--turn-port", type=int, help="TURN 服务器端口")
    parser.add_argument("--username", help="TURN 用户名")
    parser.add_argument("--password", help="TURN 密码")
    parser.add_argument("--realm", help="TURN 认证域")
    parser.add_argument("--mac", help="自定义客户端 MAC 地址 (格式: xx:xx:xx:xx:xx:xx)")
    parser.add_argument("--mode", choices=["udp", "tcp-udp"], default="udp", help="TURN 模式 (默认: udp)")
    parser.add_argument("--tls", action="store_true", help="TURN 连接使用 TLS")
    parser.add_argument("--timeout", type=int, default=10, help="等待响应的超时时间 (秒)")
    parser.add_argument("--no-disconnect", action="store_true", help="调试用，执行后保留连接")

    args = parser.parse_args()
    use_tcp_udp = args.mode == "tcp-udp"

    print(f"=== DHCP Client via {'TCP+UDP' if use_tcp_udp else 'UDP'} TURN ===")
    print(f"Target DHCP Server: {args.target_ip}:{args.target_port}")
    print(f"TURN Server: {args.turn_server or DEFAULT_TURN_SERVER}:{args.turn_port or DEFAULT_TURN_PORT}")
    print(f"Credential: {args.username or '<default>'}")

    client = DHCPTURNClient(
        target_ip=args.target_ip,
        target_port=args.target_port,
        client_port=args.client_port,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tcp_udp=use_tcp_udp,
        use_tls=args.tls,
        mac_address=args.mac,
    )

    try:
        if not client.connect():
            return 1

        if not client.send_discover():
            return 1

        response = client.receive_response(timeout=args.timeout)
        if response:
            print("[+] DHCP interaction completed")
        else:
            print("[-] No DHCP response received")

    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    except Exception as exc:
        print(f"[-] Unexpected error: {exc}")
        return 1
    finally:
        if not args.no_disconnect:
            client.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(main())

