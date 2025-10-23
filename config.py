#!/usr/bin/env python3
"""
TURN客户端配置文件
集中管理TURN服务器的连接信息和认证凭据
"""

# TURN服务器配置
DEFAULT_TURN_SERVER = "157.230.175.178"
DEFAULT_TURN_PORT = 3478

# TURN认证信息
USERNAME = "demo"
PASSWORD = "xxx"
REALM = "anjhz3.com"

# 其他配置
DEFAULT_TIMEOUT = 10  # 默认超时时间（秒）
DEFAULT_BUFFER_SIZE = 4096  # 默认缓冲区大小
DEFAULT_CHANNEL_NUMBER = 0x4000  # 默认通道号（必须在0x4000-0x4FFF范围内）

# 日志配置
LOG_LEVEL = "INFO"  # 日志级别：DEBUG, INFO, WARNING, ERROR
LOG_FORMAT = "[%(levelname)s] %(message)s"

# 测试服务器配置（用于各种协议测试）
TEST_SERVERS = {
    "http": {
        "host": "httpbin.org",
        "port": 80,
        "https_port": 443
    },
    "dns": {
        "host": "8.8.8.8",
        "port": 53
    },
    "ftp": {
        "host": "test.rebex.net",
        "port": 21,
        "username": "demo",
        "password": "password"
    },
    "smtp": {
        "host": "smtp.gmail.com",
        "port": 587
    }
}

# 协议常量
PROTOCOLS = {
    "UDP": 17,
    "TCP": 6,
    "HTTP": 80,
    "HTTPS": 443,
    "FTP": 21,
    "SMTP": 25,
    "DNS": 53
}

# STUN/TURN消息类型
STUN_MESSAGE_TYPES = {
    "BINDING_REQUEST": 0x0001,
    "ALLOCATE_REQUEST": 0x0003,
    "CREATE_PERMISSION_REQUEST": 0x0008,
    "CHANNEL_BIND_REQUEST": 0x0009,
    "CONNECT_REQUEST": 0x000a,
    "CONNECTION_BIND_REQUEST": 0x000b,
    "CONNECTION_ATTEMPT_INDICATION": 0x000c
}

# STUN属性类型
STUN_ATTRIBUTES = {
    "USERNAME": 0x0006,
    "MESSAGE_INTEGRITY": 0x0008,
    "REALM": 0x0014,
    "NONCE": 0x0015,
    "REQUESTED_TRANSPORT": 0x0019,
    "XOR_PEER_ADDRESS": 0x0012,
    "CHANNEL_NUMBER": 0x000C,
    "FINGERPRINT": 0x8028,
    "CONNECTION_ID": 0x002a
}

# DNS查询类型
DNS_QUERY_TYPES = {
    "A": 1,      # IPv4地址
    "AAAA": 28,  # IPv6地址
    "MX": 15,    # 邮件交换
    "NS": 2,     # 名称服务器
    "CNAME": 5,  # 别名
    "TXT": 16,   # 文本记录
    "SOA": 6     # 起始授权机构
}

# HTTP状态码
HTTP_STATUS_CODES = {
    200: "OK",
    201: "Created",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable"
}

# FTP响应码
FTP_RESPONSE_CODES = {
    200: "Command okay",
    220: "Service ready",
    221: "Service closing control connection",
    230: "User logged in",
    331: "User name okay, need password",
    425: "Can't open data connection",
    426: "Connection closed; transfer aborted",
    450: "Requested file action not taken",
    500: "Syntax error, command unrecognized",
    501: "Syntax error in parameters or arguments",
    502: "Command not implemented",
    530: "Not logged in"
}

def get_turn_config():
    """获取TURN服务器配置"""
    return {
        "server": DEFAULT_TURN_SERVER,
        "port": DEFAULT_TURN_PORT,
        "username": USERNAME,
        "password": PASSWORD,
        "realm": REALM
    }

def get_test_server(protocol):
    """获取指定协议的测试服务器配置"""
    return TEST_SERVERS.get(protocol.lower(), {})

def get_protocol_port(protocol):
    """获取指定协议的默认端口"""
    return PROTOCOLS.get(protocol.upper(), None)

def get_dns_query_type(query_type):
    """获取DNS查询类型"""
    if isinstance(query_type, str):
        return DNS_QUERY_TYPES.get(query_type.upper(), 1)
    return query_type

def get_http_status_message(code):
    """获取HTTP状态码对应的消息"""
    return HTTP_STATUS_CODES.get(code, "Unknown")

def get_ftp_response_message(code):
    """获取FTP响应码对应的消息"""
    return FTP_RESPONSE_CODES.get(code, "Unknown")

# 配置验证
def validate_config():
    """验证配置的有效性"""
    errors = []
    
    # 验证TURN服务器配置
    if not DEFAULT_TURN_SERVER:
        errors.append("DEFAULT_TURN_SERVER不能为空")
    
    if not (1 <= DEFAULT_TURN_PORT <= 65535):
        errors.append("DEFAULT_TURN_PORT必须在1-65535范围内")
    
    # 验证认证信息
    if not USERNAME:
        errors.append("USERNAME不能为空")
    
    if not PASSWORD:
        errors.append("PASSWORD不能为空")
    
    if not REALM:
        errors.append("REALM不能为空")
    
    # 验证通道号
    if not (0x4000 <= DEFAULT_CHANNEL_NUMBER <= 0x4FFF):
        errors.append("DEFAULT_CHANNEL_NUMBER必须在0x4000-0x4FFF范围内")
    
    if errors:
        raise ValueError("配置验证失败: " + "; ".join(errors))
    
    return True

if __name__ == "__main__":
    # 运行配置验证
    try:
        validate_config()
        print("✅ 配置验证通过")
        print(f"TURN服务器: {DEFAULT_TURN_SERVER}:{DEFAULT_TURN_PORT}")
        print(f"用户名: {USERNAME}")
        print(f"认证域: {REALM}")
    except ValueError as e:
        print(f"❌ 配置验证失败: {e}")
