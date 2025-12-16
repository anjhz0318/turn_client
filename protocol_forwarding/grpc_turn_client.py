#!/usr/bin/env python3
"""
gRPC Client via TCP TURN

参考 http_turn_client.py，通过 TURN 中继建立 TCP 连接，并在其上发起 gRPC（HTTP/2） 请求。
功能聚焦于单次请求：发送一条消息，接收响应头、数据帧和 Trailers。
"""

import argparse
import base64
import binascii
import os
import socket
import ssl
import sys
import time

try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        ResponseReceived,
        DataReceived,
        StreamEnded,
        StreamReset,
        TrailersReceived,
        SettingsAcknowledged,
    )
    from h2.settings import SettingCodes
except ImportError:
    print("[-] Missing dependency: h2 (hyper-h2). Install via 'pip install h2'")
    sys.exit(1)

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
from test_turn_capabilities import allocate_tcp_with_fallback
from turn_client import create_permission
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


class GRPCTurnClient:
    def __init__(
        self,
        target_host,
        target_port,
        turn_server=None,
        turn_port=None,
        username=None,
        password=None,
        realm=None,
        use_turn_tls=False,
        target_tls=False,
        verify_target_ssl=True,
        timeout=10,
        user_agent="grpc-turn-client/1.0",
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.turn_server = turn_server or DEFAULT_TURN_SERVER
        self.turn_port = turn_port or DEFAULT_TURN_PORT
        self.username = username
        self.password = password
        self.realm = realm
        self.use_turn_tls = use_turn_tls
        self.target_tls = target_tls
        self.verify_target_ssl = verify_target_ssl
        self.timeout = timeout
        self.user_agent = user_agent

        self.control_sock = None
        self.data_sock = None
        self.connected = False

        self.nonce = None
        self.realm_from_server = None
        self.integrity_key = None
        self.actual_turn_address = None
        self.mi_algorithm = None

        self.h2_conn = None
        self.h2_ready = False

    def connect(self):
        print(f"[+] Connecting to gRPC server {self.target_host}:{self.target_port} via TURN")
        server_address = resolve_server_address(self.turn_server, self.turn_port)
        if not server_address:
            print("[-] Failed to resolve TURN server address")
            return False
        print(f"[+] Using TURN server: {server_address}")

        try:
            allocation_result, is_short_term = allocate_tcp_with_fallback(
                server_address,
                self.username,
                self.password,
                self.realm,
                self.use_turn_tls,
            )
            if not allocation_result:
                print("[-] Failed to allocate TCP TURN relay")
                return False

            (
                self.control_sock,
                nonce,
                realm,
                integrity_key,
                actual_server_address,
                *extra,
            ) = allocation_result

            self.nonce = nonce
            self.realm_from_server = realm
            self.integrity_key = integrity_key
            self.actual_turn_address = actual_server_address
            self.mi_algorithm = extra[0] if extra else None

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
                self.realm_from_server,
                self.integrity_key,
                peer_ip,
                self.target_port,
                self.actual_turn_address,
                self.username,
                self.mi_algorithm,
            ):
                print("[-] Failed to create permission")
                self.control_sock.close()
                return False

            print(f"[+] Initiating TCP connection to {self.target_host}:{self.target_port}")
            connection_id, error_info = tcp_connect(
                self.control_sock,
                self.nonce,
                self.realm_from_server,
                self.integrity_key,
                peer_ip,
                self.target_port,
                self.username,
            )
            if not connection_id:
                if error_info:
                    print(f"[-] Failed to initiate TCP connection: {error_info.get('message', 'Unknown error')}")
                else:
                    print("[-] Failed to initiate TCP connection")
                self.control_sock.close()
                return False
            print(f"[+] Got connection ID: {connection_id}")

            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_sock.settimeout(self.timeout)
            self.data_sock.connect(self.actual_turn_address)
            print("[+] Data connection established")

            if not tcp_connection_bind(
                self.data_sock,
                self.nonce,
                self.realm_from_server,
                self.integrity_key,
                connection_id,
                self.actual_turn_address,
                self.username,
            ):
                print("[-] Failed to bind data connection")
                self.data_sock.close()
                self.control_sock.close()
                return False
            print("[+] Data connection bound successfully")

            if self.target_tls:
                print("[+] Establishing TLS with target (ALPN: h2)")
                context = ssl.create_default_context()
                context.set_alpn_protocols(["h2"])
                if not self.verify_target_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    print("[!] Target SSL verification disabled")
                self.data_sock = context.wrap_socket(self.data_sock, server_hostname=self.target_host)
                selected = None
                if hasattr(self.data_sock, "selected_alpn_protocol"):
                    selected = self.data_sock.selected_alpn_protocol()
                if selected != "h2":
                    print(f"[!] Warning: Target ALPN protocol is {selected}, expected 'h2'")

            self.connected = True
            return True
        except Exception as exc:
            print(f"[-] Connection failed: {exc}")
            if self.control_sock:
                try:
                    self.control_sock.close()
                except Exception:
                    pass
            if self.data_sock:
                try:
                    self.data_sock.close()
                except Exception:
                    pass
            return False

    def _ensure_h2(self):
        if self.h2_ready:
            return
        config = H2Configuration(client_side=True, header_encoding="utf-8")
        self.h2_conn = H2Connection(config=config)
        self._send_bytes(HTTP2_PREFACE)
        initial_data = self.h2_conn.initiate_connection()
        self._send_bytes(initial_data)
        # 请求较大的流量窗口，避免流控影响
        self.h2_conn.update_settings(
            {
                SettingCodes.MAX_FRAME_SIZE: 2 ** 14,
            }
        )
        self._flush()
        self.h2_ready = True

    def _send_bytes(self, data: bytes):
        if not data:
            return
        try:
            self.data_sock.sendall(data)
        except Exception as exc:
            raise RuntimeError(f"Failed to send data over TURN data connection: {exc}") from exc

    def _flush(self):
        to_send = self.h2_conn.data_to_send()
        if to_send:
            self._send_bytes(to_send)

    def send_grpc_request(
        self,
        path,
        payload_bytes,
        metadata=None,
        scheme=None,
        authority=None,
        timeout_ms=None,
    ):
        if not self.connected:
            raise RuntimeError("TURN connection is not established")

        self._ensure_h2()

        stream_id = self.h2_conn.get_next_available_stream_id()
        headers = [
            (":method", "POST"),
            (":path", path),
            (":scheme", scheme or ("https" if self.target_tls else "http")),
            (":authority", authority or self.target_host),
            ("te", "trailers"),
            ("content-type", "application/grpc"),
            ("user-agent", self.user_agent),
            ("grpc-accept-encoding", "identity,deflate,gzip"),
            ("grpc-encoding", "identity"),
        ]
        if timeout_ms:
            headers.append(("grpc-timeout", f"{int(timeout_ms)}m"))
        if metadata:
            for key, value in metadata.items():
                headers.append((key.lower(), value))

        end_stream = payload_bytes is None or len(payload_bytes) == 0
        header_data = self.h2_conn.send_headers(stream_id, headers, end_stream=end_stream)
        self._send_bytes(header_data)

        if not end_stream:
            grpc_frame = self._frame_grpc_message(payload_bytes)
            data_frame = self.h2_conn.send_data(stream_id, grpc_frame, end_stream=True)
            self._send_bytes(data_frame)

        self._flush()
        return self._wait_for_response(stream_id)

    @staticmethod
    def _frame_grpc_message(message_bytes: bytes) -> bytes:
        flag = b"\x00"  # uncompressed
        length = len(message_bytes).to_bytes(4, byteorder="big")
        return flag + length + message_bytes

    def _wait_for_response(self, stream_id):
        response_headers = None
        response_messages = []
        trailers = {}
        buffer = bytearray()
        stream_ended = False
        start_time = time.time()

        while not stream_ended:
            if time.time() - start_time > self.timeout:
                raise TimeoutError("Timed out waiting for gRPC response")
            try:
                chunk = self.data_sock.recv(65535)
                if not chunk:
                    raise RuntimeError("Connection closed by peer before stream ended")
                events = self.h2_conn.receive_data(chunk)
                self._flush()
                for event in events:
                    if isinstance(event, ResponseReceived):
                        response_headers = event.headers
                    elif isinstance(event, DataReceived):
                        self.h2_conn.acknowledge_received_data(event.flow_controlled_length, stream_id)
                        buffer.extend(event.data)
                    elif isinstance(event, TrailersReceived):
                        trailers = dict(event.headers)
                    elif isinstance(event, StreamEnded):
                        stream_ended = True
                    elif isinstance(event, StreamReset):
                        raise RuntimeError(f"Stream reset: {event.error_code}")
                    elif isinstance(event, SettingsAcknowledged):
                        pass
                self._flush()
            except socket.timeout:
                continue

        if buffer:
            response_messages = self._parse_grpc_buffer(buffer)

        return {
            "headers": response_headers or [],
            "messages": response_messages,
            "trailers": trailers,
        }

    @staticmethod
    def _parse_grpc_buffer(buffer: bytearray):
        messages = []
        view = memoryview(buffer)
        offset = 0
        while offset + 5 <= len(view):
            compressed_flag = view[offset]
            length = int.from_bytes(view[offset + 1 : offset + 5], byteorder="big")
            offset += 5
            if offset + length > len(view):
                break
            data = bytes(view[offset : offset + length])
            offset += length
            if compressed_flag not in (0, 1):
                compressed_flag = 0
            messages.append(
                {
                    "compressed": bool(compressed_flag),
                    "length": length,
                    "data": data,
                }
            )
        return messages

    def disconnect(self):
        if not self.connected:
            return
        print("[+] Disconnecting...")
        try:
            if self.data_sock:
                if self.target_tls and hasattr(self.data_sock, "unwrap"):
                    try:
                        self.data_sock.unwrap()
                    except Exception:
                        pass
                self.data_sock.close()
        finally:
            if self.control_sock:
                self.control_sock.close()
            self.connected = False


def load_payload(args):
    sources = [
        args.data_text is not None,
        args.data_hex is not None,
        args.data_base64 is not None,
        args.data_file is not None,
    ]
    if sum(1 for x in sources if x) > 1:
        raise ValueError("Only one of --data-text, --data-hex, --data-base64, --data-file can be specified")
    if args.data_text is not None:
        return args.data_text.encode("utf-8")
    if args.data_hex is not None:
        try:
            return binascii.unhexlify(args.data_hex.replace(" ", ""))
        except binascii.Error as exc:
            raise ValueError(f"Invalid hex data: {exc}")
    if args.data_base64 is not None:
        try:
            return base64.b64decode(args.data_base64)
        except binascii.Error as exc:
            raise ValueError(f"Invalid base64 data: {exc}")
    if args.data_file is not None:
        with open(args.data_file, "rb") as f:
            return f.read()
    return b""


def parse_metadata(metadata_str):
    metadata = {}
    if not metadata_str:
        return metadata
    pairs = metadata_str.split(",")
    for pair in pairs:
        if not pair:
            continue
        if ":" not in pair:
            raise ValueError(f"Invalid metadata entry: {pair}")
        key, value = pair.split(":", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def main():
    parser = argparse.ArgumentParser(description="gRPC client via TCP TURN")
    parser.add_argument("--target-host", required=True, help="Target server hostname/IP")
    parser.add_argument("--target-port", type=int, required=True, help="Target server port")
    parser.add_argument("--turn-server", help="TURN server hostname")
    parser.add_argument("--turn-port", type=int, help="TURN server port")
    parser.add_argument("--username", help="TURN username")
    parser.add_argument("--password", help="TURN password")
    parser.add_argument("--realm", help="TURN realm")
    parser.add_argument("--turn-tls", action="store_true", help="Use TLS for TURN connection")
    parser.add_argument("--target-tls", action="store_true", help="Wrap target connection with TLS (ALPN h2)")
    parser.add_argument("--no-verify-target-ssl", action="store_true", help="Disable target TLS certificate validation")
    parser.add_argument("--timeout", type=int, default=10, help="Overall timeout (seconds)")
    parser.add_argument("--user-agent", default="grpc-turn-client/1.0", help="gRPC User-Agent header")

    path_group = parser.add_mutually_exclusive_group(required=False)
    path_group.add_argument("--path", help="Explicit gRPC path (e.g., /package.Service/Method)")
    parser.add_argument("--service", help="gRPC service name (used with --method to build /Service/Method)")
    parser.add_argument("--method", help="gRPC method name (used with --service)")

    parser.add_argument("--data-text", help="Request payload as UTF-8 text")
    parser.add_argument("--data-hex", help="Request payload as hex string")
    parser.add_argument("--data-base64", help="Request payload as base64 string")
    parser.add_argument("--data-file", help="Read request payload from file (binary)")
    parser.add_argument("--metadata", help="Comma-separated metadata key:value pairs")
    parser.add_argument("--authority", help="Override :authority header")
    parser.add_argument("--scheme", help="Override :scheme header (default http/https)")
    parser.add_argument("--grpc-timeout-ms", type=int, help="grpc-timeout value in milliseconds")

    args = parser.parse_args()

    if args.path:
        grpc_path = args.path
    else:
        if not (args.service and args.method):
            parser.error("Either --path or both --service and --method must be provided")
        grpc_path = f"/{args.service}/{args.method}"

    try:
        payload = load_payload(args)
        metadata = parse_metadata(args.metadata)
    except ValueError as exc:
        print(f"[-] {exc}")
        return 1

    client = GRPCTurnClient(
        target_host=args.target_host,
        target_port=args.target_port,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_turn_tls=args.turn_tls,
        target_tls=args.target_tls,
        verify_target_ssl=not args.no_verify_target_ssl,
        timeout=args.timeout,
        user_agent=args.user_agent,
    )

    if not client.connect():
        return 1

    try:
        result = client.send_grpc_request(
            path=grpc_path,
            payload_bytes=payload,
            metadata=metadata,
            scheme=args.scheme,
            authority=args.authority,
            timeout_ms=args.grpc_timeout_ms,
        )
        print("\n=== gRPC Response Headers ===")
        for k, v in result["headers"]:
            print(f"{k}: {v}")

        if result["messages"]:
            print("\n=== gRPC Messages ===")
            for idx, message in enumerate(result["messages"], 1):
                flag = "compressed" if message["compressed"] else "uncompressed"
                print(f"[Message {idx}] {flag}, {message['length']} bytes")
                print(binascii.hexlify(message["data"]).decode("ascii"))
        else:
            print("\n[!] No gRPC data messages received")

        if result["trailers"]:
            print("\n=== gRPC Trailers ===")
            for k, v in result["trailers"].items():
                print(f"{k}: {v}")

        return 0
    except Exception as exc:
        print(f"[-] gRPC request failed: {exc}")
        return 1
    finally:
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())

