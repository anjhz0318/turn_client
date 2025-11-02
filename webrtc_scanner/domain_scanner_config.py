#!/usr/bin/env python3
"""
WebRTC 域名扫描器配置文件
配置 OpenRouter API 和其他扫描参数
"""

import os

# OpenRouter API 配置
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
# 如果环境变量未设置，可以在这里直接设置（不推荐，建议使用环境变量）
OPENROUTER_API_KEY = "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"

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

# 默认模型配置
DEFAULT_MODEL = "google/gemini-2.0-flash-001"  # 使用更经济的模型

# 可用的模型列表（可选）
AVAILABLE_MODELS = {
    "gpt4o-mini": "openai/gpt-4o-mini",  # 经济实惠，速度快
    "gpt4o": "openai/gpt-4o",  # 性能更好，准确性高
    "claude-haiku": "anthropic/claude-3-haiku",  # 速度快，成本低
    "gemini-flash": "google/gemini-2.0-flash-001", # 速度快，成本低
    "gemini-pro": "google/gemini-2.5-pro",  # Google 模型
    "deepseek-r1": "deepseek/deepseek-r1-0528",  # 深度求索模型
}

# HTTP 请求配置
DEFAULT_TIMEOUT = 10  # HTTP 请求超时时间（秒）
DEFAULT_MAX_CONTENT_LENGTH = 500000  # 最大页面内容长度（字符）
DEFAULT_DELAY = 1  # 请求之间的延迟（秒）

# 结果文件配置
RESULTS_FILE = "webrtc_scan_results.json"
PROGRESS_FILE = "webrtc_scan_progress.json"

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
    获取 OpenRouter API Key
    
    Returns:
        API Key 字符串，如果未设置则返回空字符串
    """
    return OPENROUTER_API_KEY


def validate_config():
    """
    验证配置的有效性
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if not OPENROUTER_API_KEY:
        return False, "OPENROUTER_API_KEY 未设置。请设置环境变量或修改配置文件。"
    
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
        print(f"OpenRouter API URL: {OPENROUTER_API_URL}")
        print(f"默认模型: {DEFAULT_MODEL}")
        print(f"API Key: {'已设置' if OPENROUTER_API_KEY else '未设置'}")
        print(f"超时时间: {DEFAULT_TIMEOUT} 秒")
        print(f"最大内容长度: {DEFAULT_MAX_CONTENT_LENGTH} 字符")
        print(f"请求延迟: {DEFAULT_DELAY} 秒")
    else:
        print(f"❌ 配置验证失败: {error}")

