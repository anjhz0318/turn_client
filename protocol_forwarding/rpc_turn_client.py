#!/usr/bin/env python3
"""
RPCBIND Client via TCP TURN
支持通过TURN服务器转发的RPCBIND (program number 100000) 查询。
目前实现：
  - RPCBPROC_NULL：用于连接性检查
  - RPCBPROC_GETADDR：查询指定RPC程序的可用地址
  - RPCBPROC_DUMP：拉取全部注册的RPC映射列表
"""

import argparse
import os
import random
import socket
import struct
import sys
from typing import Callable, List, Optional
import xdrlib

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
    tcp_send_data,
)

# 引入回退分配逻辑以及权限创建函数
from test_turn_capabilities import allocate_tcp_with_fallback
from turn_client import create_permission, tcp_receive_data
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

# RPC 常量
RPCBIND_PROGRAM = 100000
RPC_VERSION = 2
RPCBIND_VERSION = 4

RPC_CALL = 0
RPC_REPLY = 1

RPC_MSG_ACCEPTED = 0
RPC_MSG_DENIED = 1

RPC_ACCEPT_SUCCESS = 0

RPCBPROC_NULL = 0
RPCBPROC_SET = 1
RPCBPROC_UNSET = 2
RPCBPROC_GETADDR = 3
RPCBPROC_DUMP = 4

AUTH_NULL = 0


class RPCBindTURNClient:
    def __init__(
        self,
        target_host: str,
        target_port: int = 111,
        turn_server: Optional[str] = None,
        turn_port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        realm: Optional[str] = None,
        use_tls: bool = False,
        timeout: int = 10,
        rpc_version: int = RPCBIND_VERSION,
        debug: bool = False,
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.turn_server = turn_server or DEFAULT_TURN_SERVER
        self.turn_port = turn_port or DEFAULT_TURN_PORT
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls
        self.timeout = timeout
        self.rpc_version = rpc_version
        self.debug = debug

        self.control_sock = None
        self.data_sock = None
        self.connected = False
        self._nonce = None
        self._realm = None
        self._integrity_key = None
        self._actual_server_address = None
        self._mi_algorithm = None

    def connect(self) -> bool:
        """建立到目标RPCBIND服务的TURN转发连接。"""
        print(f"[+] Connecting to RPCBIND {self.target_host}:{self.target_port} via TURN")

        # 解析TURN服务器地址
        server_address = resolve_server_address(self.turn_server, self.turn_port)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return False

        print(f"[+] Using TURN server: {server_address}")

        try:
            # 1. 分配TCP中继（带回退机制）
            allocation_result, is_short_term = allocate_tcp_with_fallback(
                server_address, self.username, self.password, self.realm, self.use_tls
            )
            if not allocation_result:
                print("[-] Failed to allocate TCP TURN relay")
                return False

            (
                self.control_sock,
                self._nonce,
                self._realm,
                self._integrity_key,
                self._actual_server_address,
                *extra,
            ) = allocation_result
            self._mi_algorithm = extra[0] if extra else None

            if is_short_term:
                print("[+] TURN allocation successful (short-term credential)")
            else:
                print("[+] TURN allocation successful (long-term credential)")

            # 2. 解析目标主机
            peer_ip = resolve_peer_address(self.target_host)
            if not peer_ip:
                print(f"[-] Failed to resolve peer {self.target_host}")
                self.control_sock.close()
                return False

            print(f"[+] Resolved peer {self.target_host} to {peer_ip}")

            # 3. 创建权限
            if not create_permission(
                self.control_sock,
                self._nonce,
                self._realm,
                self._integrity_key,
                peer_ip,
                self.target_port,
                self._actual_server_address,
                self.username,
                self._mi_algorithm,
            ):
                print("[-] Failed to create permission")
                self.control_sock.close()
                return False

            # 4. 发起TCP连接
            print(f"[+] Initiating TCP connection to {self.target_host}:{self.target_port}")
            connection_id = tcp_connect(
                self.control_sock,
                self._nonce,
                self._realm,
                self._integrity_key,
                peer_ip,
                self.target_port,
                self.username,
            )
            if not connection_id:
                print("[-] Failed to initiate TCP connection")
                self.control_sock.close()
                return False

            print(f"[+] Got connection ID: {connection_id}")

            # 5. 建立数据连接
            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_sock.settimeout(self.timeout)
            self.data_sock.connect(self._actual_server_address)
            print("[+] Data connection established")

            # 6. 绑定数据连接
            if not tcp_connection_bind(
                self.data_sock,
                self._nonce,
                self._realm,
                self._integrity_key,
                connection_id,
                self._actual_server_address,
                self.username,
                self._mi_algorithm,
            ):
                print("[-] Failed to bind data connection")
                self.data_sock.close()
                self.control_sock.close()
                return False

            print("[+] Data connection bound successfully")

            self.connected = True
            return True

        except Exception as exc:
            print(f"[-] Connection failed: {exc}")
            if self.control_sock:
                self.control_sock.close()
            if self.data_sock:
                self.data_sock.close()
            return False

    def call_null(self) -> bool:
        """执行 RPCBPROC_NULL 检测服务可达性。"""
        unpacker = self._perform_call(RPCBPROC_NULL)
        if not unpacker:
            return False
        print("[+] RPCBPROC_NULL call succeeded")
        return True

    def call_getaddr(self, program: int, version: int, netid: str, owner: str = "") -> Optional[str]:
        """执行 RPCBPROC_GETADDR 查询指定RPC程序的地址。"""

        def _args(packer: xdrlib.Packer) -> None:
            packer.pack_uint(program)
            packer.pack_uint(version)
            packer.pack_string(netid.encode("utf-8"))
            packer.pack_string(b"")  # universal address (unused in query)
            packer.pack_string(owner.encode("utf-8"))

        unpacker = self._perform_call(RPCBPROC_GETADDR, args_builder=_args)
        if not unpacker:
            return None

        try:
            address = unpacker.unpack_string().decode("utf-8", errors="ignore")
        except Exception as exc:
            print(f"[-] Failed to parse GETADDR response: {exc}")
            return None

        print(f"[+] RPCBPROC_GETADDR result: {address or '<empty>'}")
        return address

    def call_dump(self) -> Optional[List[dict]]:
        """执行 RPCBPROC_DUMP 拉取全部 RPC 映射。"""
        unpacker = self._perform_call(RPCBPROC_DUMP)
        if not unpacker:
            return None

        entries: List[dict] = []

        def _parse_list() -> None:
            has_value = unpacker.unpack_uint()
            if has_value == 0:
                return
            entry = {
                "program": unpacker.unpack_uint(),
                "version": unpacker.unpack_uint(),
                "netid": unpacker.unpack_string().decode("utf-8", errors="ignore"),
                "address": unpacker.unpack_string().decode("utf-8", errors="ignore"),
                "owner": unpacker.unpack_string().decode("utf-8", errors="ignore"),
            }
            entries.append(entry)
            _parse_list()

        try:
            _parse_list()
        except Exception as exc:
            print(f"[-] Failed to parse DUMP response: {repr(exc)}")
            return None

        print(f"[+] RPCBPROC_DUMP returned {len(entries)} entries")
        return entries

    def disconnect(self) -> None:
        if self.connected:
            print("[+] Disconnecting...")
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

    # Internal helpers -----------------------------------------------------
    def _perform_call(
        self,
        procedure: int,
        args_builder: Optional[Callable[[xdrlib.Packer], None]] = None,
    ) -> Optional[xdrlib.Unpacker]:
        if not self.connected:
            print("[-] Not connected")
            return None

        xid = random.getrandbits(32)
        request = self._build_rpc_call(
            xid=xid,
            procedure=procedure,
            args_builder=args_builder,
        )

        if not tcp_send_data(self.data_sock, request):
            print("[-] Failed to send RPC request")
            return None

        response = self._receive_rpc_record()
        if not response:
            print("[-] No response received from RPCBIND")
            return None

        if self.debug:
            print(f"[DEBUG] RPC response length: {len(response)} bytes")
            print(f"[DEBUG] RPC response (hex): {response.hex()}")

        try:
            unpacker = xdrlib.Unpacker(response)
            rxid = unpacker.unpack_uint()
            if rxid != xid:
                print(f"[!] XID mismatch: sent {xid}, got {rxid}")
            msg_type = unpacker.unpack_uint()
            if msg_type != RPC_REPLY:
                print(f"[-] Unexpected RPC message type: {msg_type}")
                return None
            reply_stat = unpacker.unpack_uint()
            if reply_stat != RPC_MSG_ACCEPTED:
                print(f"[-] RPC reply denied (status={reply_stat})")
                return None

            self._unpack_auth(unpacker)  # verifier

            accept_stat = unpacker.unpack_uint()
            if accept_stat != RPC_ACCEPT_SUCCESS:
                print(f"[-] RPC accept failed (status={accept_stat})")
                return None

            return unpacker
        except Exception as exc:
            print(f"[-] Failed to decode RPC reply: {exc}")
            return None

    def _build_rpc_call(
        self,
        xid: int,
        procedure: int,
        args_builder: Optional[Callable[[xdrlib.Packer], None]] = None,
    ) -> bytes:
        packer = xdrlib.Packer()
        packer.pack_uint(xid)
        packer.pack_uint(RPC_CALL)
        packer.pack_uint(RPC_VERSION)
        packer.pack_uint(RPCBIND_PROGRAM)
        packer.pack_uint(self.rpc_version)
        packer.pack_uint(procedure)

        # Credentials: AUTH_NULL
        packer.pack_uint(AUTH_NULL)
        packer.pack_bytes(b"")

        # Verifier: AUTH_NULL
        packer.pack_uint(AUTH_NULL)
        packer.pack_bytes(b"")

        if args_builder:
            args_builder(packer)

        payload = packer.get_buffer()
        record_marker = struct.pack("!I", len(payload) | 0x80000000)
        return record_marker + payload

    def _receive_rpc_record(self) -> Optional[bytes]:
        """接收一个完整的RPC记录（处理记录分片）。"""
        if not self.data_sock:
            return None

        fragments = []
        total_length = 0
        while True:
            header = self._recv_exact(4)
            if not header:
                return None
            (word,) = struct.unpack("!I", header)
            last_fragment = bool(word & 0x80000000)
            length = word & 0x7FFFFFFF
            total_length += length
            if self.debug:
                print(f"[DEBUG] Fragment header: last={last_fragment} length={length}")
            if length == 0:
                fragments.append(b"")
            else:
                fragment = self._recv_exact(length)
                if fragment is None:
                    return None
                fragments.append(fragment)
            if last_fragment:
                break
        if self.debug:
            print(f"[DEBUG] Total RPC payload length: {total_length} bytes")
        return b"".join(fragments)

    def _recv_exact(self, size: int) -> Optional[bytes]:
        """从数据socket中读取指定字节数。"""
        data = b""
        while len(data) < size:
            try:
                chunk = self.data_sock.recv(size - len(data))
            except socket.timeout:
                print("[-] Timeout while receiving RPC response")
                return None
            except Exception as exc:
                print(f"[-] Error receiving RPC response: {exc}")
                return None
            if not chunk:
                print("[-] Connection closed while receiving RPC response")
                return None
            data += chunk
        return data

    @staticmethod
    def _unpack_auth(unpacker: xdrlib.Unpacker) -> dict:
        flavor = unpacker.unpack_uint()
        data = unpacker.unpack_bytes()
        return {"flavor": flavor, "data": data}


def main() -> int:
    parser = argparse.ArgumentParser(description="RPCBIND Client via TCP TURN")
    parser.add_argument("--target-host", required=True, help="目标RPCBIND主机名")
    parser.add_argument("--target-port", type=int, default=111, help="目标RPCBIND端口 (默认: 111)")
    parser.add_argument("--turn-server", help="TURN服务器地址")
    parser.add_argument("--turn-port", type=int, help="TURN服务器端口")
    parser.add_argument("--username", help="TURN用户名")
    parser.add_argument("--password", help="TURN密码")
    parser.add_argument("--realm", help="TURN认证域")
    parser.add_argument("--tls", action="store_true", help="与TURN服务器建立TLS连接")
    parser.add_argument("--timeout", type=int, default=10, help="RPC响应超时时间（秒）")
    parser.add_argument("--rpc-version", type=int, default=RPCBIND_VERSION, help="RPCBIND版本 (默认: 4)")
    parser.add_argument(
        "--procedure",
        choices=["null", "getaddr", "dump"],
        default="dump",
        help="要执行的RPCBIND操作",
    )
    parser.add_argument("--program", type=int, help="GETADDR需要查询的RPC程序号")
    parser.add_argument("--program-version", type=int, help="GETADDR需要查询的RPC程序版本号")
    parser.add_argument("--netid", default="tcp", help="GETADDR查询使用的网络ID (默认: tcp)")
    parser.add_argument("--owner", default="", help="GETADDR查询的owner字段 (默认: 空)")
    parser.add_argument("--debug", action="store_true", help="输出RPC原始响应调试信息")

    args = parser.parse_args()

    print("=== RPCBIND Client via TCP TURN ===")
    print(f"Target: {args.target_host}:{args.target_port}")
    print(f"TURN Server: {args.turn_server or DEFAULT_TURN_SERVER}:{args.turn_port or DEFAULT_TURN_PORT}")
    print(f"Procedure: {args.procedure}")

    client = RPCBindTURNClient(
        target_host=args.target_host,
        target_port=args.target_port,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tls=args.tls,
        timeout=args.timeout,
        rpc_version=args.rpc_version,
        debug=args.debug,
    )

    try:
        if not client.connect():
            print("[-] Failed to connect via TURN")
            return 1

        if args.procedure == "null":
            success = client.call_null()
            return 0 if success else 1

        if args.procedure == "getaddr":
            if args.program is None or args.program_version is None:
                print("[-] --program 和 --program-version 是 GETADDR 必需参数")
                return 1
            result = client.call_getaddr(args.program, args.program_version, args.netid, args.owner)
            if result is None:
                return 1
            print(f"\nUniversal address: {result or '<empty>'}")
            return 0

        # 默认执行dump
        entries = client.call_dump()
        if entries is None:
            return 1

        if not entries:
            print("[+] RPCBIND registry is empty")
            return 0

        print("\n=== RPCBIND Registry Entries ===")
        for idx, entry in enumerate(entries, start=1):
            print(f"#{idx}: program={entry['program']} version={entry['version']} "
                  f"netid={entry['netid']} address={entry['address']} owner={entry['owner']}")
        return 0

    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
        return 1
    finally:
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())

