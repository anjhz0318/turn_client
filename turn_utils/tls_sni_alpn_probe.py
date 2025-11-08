#!/usr/bin/env python3
"""
TLS SNI / ALPN 探测脚本
用于诊断服务端是否根据不同的 SNI / ALPN 进行协议分流。
"""

import argparse
import socket
import ssl
import time
from typing import Iterable, List, Optional, Tuple


def _parse_alpn(value: str) -> List[str]:
    """
    将命令行传入的 ALPN 字符串解析为列表。
    支持使用逗号分隔多个 ALPN，使用 "none" 表示不发送 ALPN。
    """
    if value is None:
        return []
    value = value.strip()
    if not value or value.lower() == "none":
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _format_subject(cert: dict) -> str:
    """从证书信息中提取 subject 字段用于展示。"""
    if not cert:
        return "N/A"
    subject = cert.get("subject", [])
    parts: List[str] = []
    for entry in subject:
        # entry 形式如 ((('commonName', 'example.com'),), ...)
        for key, value in entry:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else "N/A"


def iterate_combinations(
    host: str,
    snis: Optional[Iterable[str]],
    alpn_sets: Optional[Iterable[str]]
) -> List[Tuple[Optional[str], List[str]]]:
    """
    生成待测试的 (SNI, ALPN 列表) 组合。
    """
    sni_candidates: List[Optional[str]]
    if snis:
        sni_candidates = [
            None if (sni is None or sni.lower() == "none") else sni
            for sni in snis
        ]
    else:
        # 默认测试：不发送 SNI + 使用目标域名作为 SNI
        sni_candidates = [None, host]

    if alpn_sets:
        alpn_candidates = [_parse_alpn(val) for val in alpn_sets]
    else:
        # 默认测试：不发送 ALPN、只发送 http/1.1、发送 TURN/STUN 常见标识
        alpn_candidates = [
            [],
            ["http/1.1"],
            ["h2", "http/1.1"],
            ["turn"],
            ["stun.turn"],
            ["webrtc", "turn"]
        ]

    combinations: List[Tuple[Optional[str], List[str]]] = []
    for sni in sni_candidates:
        for alpn in alpn_candidates:
            combinations.append((sni, alpn))
    return combinations


def perform_handshake(
    host: str,
    port: int,
    sni: Optional[str],
    alpn: List[str],
    timeout: float,
    insecure: bool
) -> Tuple[bool, dict]:
    """
    执行一次 TLS 握手并返回结果。
    result 字典包括：
        - handshake_time
        - negotiated_alpn
        - cipher
        - subject
    """
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    if alpn:
        context.set_alpn_protocols(alpn)

    info: dict = {
        "sni": sni if sni is not None else "None",
        "alpn": alpn or ["<none>"],
        "error": None,
        "handshake_time": None,
        "negotiated_alpn": None,
        "cipher": None,
        "subject": None,
    }

    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if sni is not None:
                tls_sock = context.wrap_socket(sock, server_hostname=sni)
            else:
                tls_sock = context.wrap_socket(sock)

            handshake_time = time.monotonic() - start
            info["handshake_time"] = handshake_time
            info["negotiated_alpn"] = tls_sock.selected_alpn_protocol() or "<none>"
            info["cipher"] = tls_sock.cipher()[0] if tls_sock.cipher() else "N/A"
            info["subject"] = _format_subject(tls_sock.getpeercert())

            # 关闭 TLS 连接
            tls_sock.close()
        return True, info
    except Exception as exc:  # 捕获所有异常，便于诊断
        info["error"] = repr(exc)
        return False, info


def main() -> None:
    parser = argparse.ArgumentParser(
        description="测试不同 SNI / ALPN 组合的 TLS 握手行为"
    )
    parser.add_argument("host", help="目标主机名或 IP")
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="目标端口（默认 443）"
    )
    parser.add_argument(
        "--sni",
        action="append",
        help="指定待测试的 SNI 值，可多次使用；填 'none' 或留空表示不发送 SNI"
    )
    parser.add_argument(
        "--alpn",
        action="append",
        help="指定待测试的 ALPN 集合，使用逗号分隔；填 'none' 表示不发送 ALPN，可多次使用"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="TCP 连接超时时间（秒，默认 5）"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="禁用证书验证（测试非匹配 SNI 时建议开启）"
    )

    args = parser.parse_args()

    combinations = iterate_combinations(args.host, args.sni, args.alpn)
    print("============================================================")
    print("TLS SNI / ALPN 探测")
    print("============================================================")
    print(f"目标: {args.host}:{args.port}")
    print(f"组合总数: {len(combinations)}")
    print(f"证书验证: {'关闭' if args.insecure else '开启'}")
    print()

    for idx, (sni, alpn) in enumerate(combinations, start=1):
        alpn_display = ", ".join(alpn) if alpn else "<none>"
        sni_display = sni if sni else "<none>"
        print(f"[{idx}/{len(combinations)}] SNI={sni_display} | ALPN={alpn_display}")

        success, info = perform_handshake(
            host=args.host,
            port=args.port,
            sni=sni,
            alpn=alpn,
            timeout=args.timeout,
            insecure=args.insecure
        )

        if success:
            print("  [+] 握手成功")
            print(f"      ⮕ 耗时: {info['handshake_time']:.3f}s")
            print(f"      ⮕ 协商 ALPN: {info['negotiated_alpn']}")
            print(f"      ⮕ 密码套件: {info['cipher']}")
            print(f"      ⮕ 证书 Subject: {info['subject']}")
        else:
            print("  [!] 握手失败")
            print(f"      ⮕ 错误: {info['error']}")

        print()

    print("探测完成。")


if __name__ == "__main__":
    main()


