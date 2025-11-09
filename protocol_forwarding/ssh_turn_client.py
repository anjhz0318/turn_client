#!/usr/bin/env python3
"""
SSH Client via TCP TURN

建立至目标主机 SSH 端口的 TURN 隧道，并打印 SSH banner。
"""

import argparse
import os
import socket
import sys
from typing import Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
TURN_UTILS_DIR = os.path.join(PROJECT_ROOT, "turn_utils")

for path in (PROJECT_ROOT, TURN_UTILS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from turn_utils import (
    resolve_server_address,
    resolve_peer_address,
    tcp_connect,
    tcp_connection_bind,
)
# 导入回退机制函数和权限创建函数
from test_turn_capabilities import allocate_tcp_with_fallback
from turn_client import create_permission
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT


class SSHTURNClient:
    """通过 TURN 服务器访问 SSH 服务"""

    def __init__(
        self,
        target_host: str,
        target_port: int = 22,
        turn_server: Optional[str] = None,
        turn_port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        realm: Optional[str] = None,
        use_tls: bool = False,
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.turn_server = turn_server or DEFAULT_TURN_SERVER
        self.turn_port = turn_port or DEFAULT_TURN_PORT
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls

        self.control_sock = None
        self.data_sock = None
        self.connected = False
        self.actual_server_address = None
        self.nonce = None
        self.realm_value = None
        self.integrity_key = None
        self.mi_algorithm = None

    def connect(self) -> bool:
        print(f"[+] Connecting to SSH server {self.target_host}:{self.target_port} via TURN")

        server_address = resolve_server_address(self.turn_server, self.turn_port)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return False

        print(f"[+] Using TURN server: {server_address}")

        allocation_result, is_short_term = allocate_tcp_with_fallback(
            server_address,
            self.username,
            self.password,
            self.realm,
            self.use_tls,
        )

        if not allocation_result:
            print("[-] Failed to allocate TCP TURN relay")
            return False

        self.control_sock, self.nonce, self.realm_value, self.integrity_key, self.actual_server_address, *extra = allocation_result
        if extra:
            self.mi_algorithm = extra[0]

        if is_short_term:
            print("[+] TCP TURN allocation successful (using short-term credential)")
        else:
            print("[+] TCP TURN allocation successful (using long-term credential)")

        peer_ip = resolve_peer_address(self.target_host)
        if not peer_ip:
            print(f"[-] Failed to resolve peer {self.target_host}")
            self.control_sock.close()
            return False

        print(f"[+] Resolved peer {self.target_host} to {peer_ip}")

        if not create_permission(
            self.control_sock,
            self.nonce,
            self.realm_value,
            self.integrity_key,
            peer_ip,
            self.target_port,
            self.actual_server_address,
            self.username,
            self.mi_algorithm,
        ):
            print("[-] Failed to create permission")
            self.control_sock.close()
            return False

        print(f"[+] Initiating TCP connection to {self.target_host}:{self.target_port}")
        connection_id = tcp_connect(
            self.control_sock,
            self.nonce,
            self.realm_value,
            self.integrity_key,
            peer_ip,
            self.target_port,
            self.username,
            self.mi_algorithm,
        )
        if not connection_id:
            print("[-] Failed to initiate TCP connection")
            self.control_sock.close()
            return False

        print(f"[+] Got connection ID: {connection_id}")

        self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data_sock.settimeout(10)
        self.data_sock.connect(self.actual_server_address)
        print("[+] Data connection established")

        if not tcp_connection_bind(
            self.data_sock,
            self.nonce,
            self.realm_value,
            self.integrity_key,
            connection_id,
            self.actual_server_address,
            self.username,
            self.mi_algorithm,
        ):
            print("[-] Failed to bind data connection")
            self.data_sock.close()
            self.control_sock.close()
            return False

        print("[+] Data connection bound successfully")
        self.connected = True
        return True

    def exchange_banner(self, send_banner: bool = True) -> None:
        if not self.connected or not self.data_sock:
            print("[-] Not connected")
            return

        try:
            banner = self.data_sock.recv(1024)
            if banner:
                print("[+] Received SSH banner:")
                print(banner.decode(errors='ignore').strip())
            else:
                print("[!] No banner received")
        except socket.timeout:
            print("[!] Timeout while waiting for banner (server silent)")
            banner = None
        except Exception as exc:
            print(f"[-] Error while receiving banner: {exc}")
            banner = None

        if send_banner:
            try:
                client_id = b"SSH-2.0-TURNProxyClient\r\n"
                self.data_sock.sendall(client_id)
                print(f"[+] Sent client identification: {client_id.decode().strip()}")
            except Exception as exc:
                print(f"[-] Failed to send client banner: {exc}")
                return

        if banner is None or not banner.strip():
            # 再尝试读取一次，看看服务器是否在我们发送后返回 banner
            try:
                banner2 = self.data_sock.recv(1024)
                if banner2:
                    print("[+] Received SSH banner after sending identification:")
                    print(banner2.decode(errors='ignore').strip())
                else:
                    print("[!] Server closed connection without banner")
            except socket.timeout:
                print("[!] Still no banner received after sending identification")
            except Exception as exc:
                print(f"[-] Error during second receive: {exc}")

    def disconnect(self):
        if self.data_sock:
            try:
                self.data_sock.close()
            except Exception:
                pass
        if self.control_sock:
            try:
                self.control_sock.close()
            except Exception:
                pass
        self.connected = False
        print("[+] Disconnected")


def main():
    parser = argparse.ArgumentParser(description="SSH Client via TCP TURN")
    parser.add_argument("--target-host", required=True, help="Target SSH server hostname/IP")
    parser.add_argument("--target-port", type=int, default=22, help="Target SSH server port")
    parser.add_argument("--turn-server", help="TURN server hostname")
    parser.add_argument("--turn-port", type=int, help="TURN server port")
    parser.add_argument("--username", help="TURN username")
    parser.add_argument("--password", help="TURN password")
    parser.add_argument("--realm", help="TURN realm")
    parser.add_argument("--tls", action="store_true", help="Use TLS for TURN connection")
    parser.add_argument("--no-send-banner", action="store_true", help="Do not send SSH client banner")
    args = parser.parse_args()

    client = SSHTURNClient(
        target_host=args.target_host,
        target_port=args.target_port,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tls=args.tls,
    )

    try:
        if client.connect():
            client.exchange_banner(send_banner=not args.no_send_banner)
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
