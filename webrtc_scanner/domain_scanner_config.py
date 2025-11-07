#!/usr/bin/env python3
"""
WebRTC 域名扫描器配置文件
配置智增增 (zhizengzeng) API 和其他扫描参数
"""

import os
from pathlib import Path

# 尝试加载 .env 文件
try:
    from dotenv import load_dotenv
    # 获取配置文件所在目录
    config_dir = Path(__file__).parent
    env_file = config_dir / '.env'
    # 如果 .env 文件存在，则加载它
    if env_file.exists():
        load_dotenv(env_file)
except ImportError:
    # 如果 python-dotenv 未安装，跳过 .env 文件加载
    pass

# 智增增 API 配置
# 优先级：环境变量 > .env 文件 > 空字符串
# 支持 OPENROUTER_API_KEY 和 API_SECRET_KEY 两种环境变量名（向后兼容）
API_KEY = os.getenv("API_SECRET_KEY") or os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_API_KEY = API_KEY  # 保持向后兼容

# 智增增 API Base URL（兼容 OpenAI API 格式）
API_BASE_URL = "https://api.zhizengzeng.com/v1"
OPENROUTER_API_URL = f"{API_BASE_URL}/chat/completions"  # 保持向后兼容

# 默认模型配置
# 注意：智增增的模型名称不需要前缀（如 google/、openai/ 等）
DEFAULT_MODEL = "gemini-2.0-flash-exp"  # 使用更经济的模型

# 可用的模型列表（可选）
# 智增增支持的模型名称格式：直接使用模型名，不需要前缀
AVAILABLE_MODELS = {
    "gpt4o-mini": "gpt-4o-mini",  # OpenAI 模型
    "gpt4o": "gpt-4o",  # OpenAI 模型
    "claude-haiku": "claude-3-haiku",  # Anthropic 模型
    "gemini-flash": "gemini-2.0-flash-exp",  # Google Gemini 模型（快速）
    "gemini-pro": "gemini-2.5-pro",  # Google Gemini 模型（准确）
    "deepseek-r1": "deepseek-r1",  # DeepSeek 模型
}

# HTTP 请求配置
DEFAULT_TIMEOUT = 10  # HTTP 请求超时时间（秒）
DEFAULT_MAX_CONTENT_LENGTH = 500000  # 最大页面内容长度（字符）
DEFAULT_DELAY = 1  # 请求之间的延迟（秒）

# 结果文件配置
RESULTS_FILE_PREFIX = "webrtc_scan_results"  # 结果文件前缀
RESULTS_FILE_SUFFIX = ".json"  # 结果文件后缀
PROGRESS_FILE = "webrtc_scan_progress.json"
BATCH_SIZE = 1000  # 每个文件保存的域名数量

# CSV 文件配置
DEFAULT_CSV_FILE = "../tranco_top_1m_domains/top-1m.csv"  # 相对于脚本目录

# User-Agent 配置（更新到较新的 Chrome 版本）
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# 请求头配置（模拟真实浏览器）
REQUEST_HEADERS = {
    # User-Agent: 模拟 Chrome 浏览器
    'User-Agent': USER_AGENT,
    
    # Accept: 浏览器接受的内容类型
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    
    # Accept-Language: 浏览器接受的语言
    'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
    
    # Accept-Encoding: 浏览器接受的编码方式
    # 注意：如果服务器返回 br (Brotli) 压缩，requests 需要 brotli 库才能自动解压
    # 如果没有安装 brotli，可以改为只接受 gzip, deflate
    'Accept-Encoding': 'gzip, deflate',  # 暂时移除 br，避免需要额外的 brotli 库
    
    # Connection: 连接类型
    'Connection': 'keep-alive',
    
    # Upgrade-Insecure-Requests: 自动升级 HTTP 到 HTTPS
    'Upgrade-Insecure-Requests': '1',
    
    # Sec-Fetch-Dest: 请求目标
    'Sec-Fetch-Dest': 'document',
    
    # Sec-Fetch-Mode: 请求模式
    'Sec-Fetch-Mode': 'navigate',
    
    # Sec-Fetch-Site: 请求来源（none 表示直接访问）
    'Sec-Fetch-Site': 'none',
    
    # Sec-Fetch-User: 是否为用户触发的请求
    'Sec-Fetch-User': '?1',
    
    # Sec-Ch-Ua: 浏览器品牌信息
    'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    
    # Sec-Ch-Ua-Mobile: 是否为移动设备
    'Sec-Ch-Ua-Mobile': '?0',
    
    # Sec-Ch-Ua-Platform: 操作系统平台
    'Sec-Ch-Ua-Platform': '"Windows"',
    
    # Cache-Control: 缓存控制
    'Cache-Control': 'max-age=0',
    
    # DNT: Do Not Track
    'DNT': '1',
}

# AI 分析配置
AI_TEMPERATURE = 0.3  # AI 模型的温度参数（0-1，越低越确定）
AI_STREAM_TIMEOUT = 60  # AI 流式响应超时时间（秒）

# WebRTC 相关关键词（用于快速预筛选，可选）
WEBRTC_KEYWORDS = [
    "webrtc", "rtcpeerconnection", "mediastream", "getusermedia",
    "stun", "turn", "ice", "sdp", "rtc", "webrtc.js",
    "simplewebrtc", "peerjs", "socket.io", "video conference",
    "video chat", "screen sharing", "real-time communication"
]


def get_api_key():
    """
    获取智增增 API Key
    
    Returns:
        API Key 字符串，如果未设置则返回空字符串
    """
    return API_KEY


def validate_config():
    """
    验证配置的有效性
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if not API_KEY:
        return False, "API Key 未设置。请在 .env 文件中设置 API_SECRET_KEY 或 OPENROUTER_API_KEY，或设置环境变量。"
    
    if not DEFAULT_MODEL:
        return False, "DEFAULT_MODEL 未设置。"
    
    if DEFAULT_TIMEOUT <= 0:
        return False, "DEFAULT_TIMEOUT 必须大于 0。"
    
    if DEFAULT_MAX_CONTENT_LENGTH <= 0:
        return False, "DEFAULT_MAX_CONTENT_LENGTH 必须大于 0。"
    
    return True, ""


if __name__ == "__main__":
    # 运行配置验证
    is_valid, error = validate_config()
    
    if is_valid:
        print("✅ 配置验证通过")
        print(f"智增增 API Base URL: {API_BASE_URL}")
        print(f"API 端点: {OPENROUTER_API_URL}")
        print(f"默认模型: {DEFAULT_MODEL}")
        print(f"API Key: {'已设置' if API_KEY else '未设置'}")
        print(f"超时时间: {DEFAULT_TIMEOUT} 秒")
        print(f"最大内容长度: {DEFAULT_MAX_CONTENT_LENGTH} 字符")
        print(f"请求延迟: {DEFAULT_DELAY} 秒")
    else:
        print(f"❌ 配置验证失败: {error}")

