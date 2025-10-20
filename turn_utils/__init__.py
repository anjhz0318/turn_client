"""
TURN工具包 - 提供TURN协议相关的核心功能

本包包含以下模块：
- turn_client: TURN客户端核心实现
- test_turn_capabilities: TURN服务器能力测试工具
- turn_server_discovery: TURN服务器发现工具

主要功能：
1. UDP TURN: 通过UDP通道发送数据
2. TCP TURN: 通过TCP连接发送数据（RFC 6062扩展）
3. TCP+UDP TURN: TCP连接但UDP中继
4. 服务器能力测试和发现
"""

# 导入核心TURN客户端功能
from .turn_client import (
    # 核心分配函数
    allocate,
    allocate_tcp,
    allocate_tcp_udp,
    
    # 权限和通道管理
    create_permission,
    channel_bind,
    channel_data,
    channel_data_tcp,
    
    # TCP连接管理
    tcp_connect,
    tcp_connection_bind,
    tcp_send_data,
    tcp_receive_data,
    
    # 地址解析
    resolve_server_address,
    resolve_peer_address,
    
    # 常量
    STUN_MAGIC_COOKIE,
    STUN_ALLOCATE_REQUEST,
    STUN_CREATE_PERMISSION_REQUEST,
    STUN_CHANNEL_BIND_REQUEST,
    STUN_CONNECT_REQUEST,
    STUN_CONNECTION_BIND_REQUEST,
)

# 导入测试工具
from .test_turn_capabilities import (
    test_udp_turn,
    test_tcp_udp_turn,
    test_tcp_turn,
)

# 导入服务器发现工具
from .turn_server_discovery import TURNServerDiscovery

__version__ = "1.0.0"
__author__ = "TURN Client Team"

# 定义公开的API
__all__ = [
    # 核心分配函数
    'allocate',
    'allocate_tcp', 
    'allocate_tcp_udp',
    
    # 权限和通道管理
    'create_permission',
    'channel_bind',
    'channel_data',
    'channel_data_tcp',
    
    # TCP连接管理
    'tcp_connect',
    'tcp_connection_bind',
    'tcp_send_data',
    'tcp_receive_data',
    
    # 地址解析
    'resolve_server_address',
    'resolve_peer_address',
    
    # 测试工具
    'test_udp_turn',
    'test_tcp_udp_turn', 
    'test_tcp_turn',
    
    # 服务器发现
    'TURNServerDiscovery',
    
    # 常量
    'STUN_MAGIC_COOKIE',
    'STUN_ALLOCATE_REQUEST',
    'STUN_CREATE_PERMISSION_REQUEST',
    'STUN_CHANNEL_BIND_REQUEST',
    'STUN_CONNECT_REQUEST',
    'STUN_CONNECTION_BIND_REQUEST',
]
