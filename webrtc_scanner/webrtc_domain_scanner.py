#!/usr/bin/env python3
"""
WebRTC 域名扫描器
从 Tranco Top 1M 域名列表中读取域名，访问主页内容，使用 AI 模型判断是否包含 WebRTC 相关服务
"""

import os
import sys
import csv
import json
import time
import argparse
import requests
from typing import Optional, Dict, List
from datetime import datetime
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# 导入配置文件
from domain_scanner_config import (
    OPENROUTER_API_URL,
    OPENROUTER_API_KEY,
    get_api_key,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT,
    DEFAULT_MAX_CONTENT_LENGTH,
    DEFAULT_DELAY,
    DEFAULT_CSV_FILE,
    REQUEST_HEADERS,
    AI_TEMPERATURE,
    AI_STREAM_TIMEOUT,
    RESULTS_FILE,
    PROGRESS_FILE,
    validate_config
)

# 全局变量用于优雅退出
interrupted = False

# 全局锁用于文件读写保护
file_lock = threading.Lock()
results_lock = threading.Lock()  # 用于保护 results 列表


def signal_handler(sig, frame):
    """处理 Ctrl+C 信号，优雅退出"""
    global interrupted
    print("\n[!] 接收到中断信号，正在保存进度...")
    interrupted = True
    # 确保保存当前进度
    try:
        results = load_results()
        if results:
            # 找到最后一个处理的域名行号
            last_line = max((r.get("line", 0) for r in results), default=1)
            save_progress(last_line, results)
            print(f"[+] 进度已保存，最后处理的行号: {last_line}")
    except Exception as e:
        print(f"[!] 保存进度时出错: {e}")


signal.signal(signal.SIGINT, signal_handler)


def read_domains(csv_file: str, start_line: Optional[int] = None, max_domains: Optional[int] = None) -> List[Dict]:
    """
    从 CSV 文件读取域名列表
    
    Args:
        csv_file: CSV 文件路径
        start_line: 从第几行开始读取（1-based）
        max_domains: 最多读取多少个域名
        
    Returns:
        域名列表，每个元素包含 rank 和 domain
    """
    domains = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for line_num, row in enumerate(reader, start=1):
            if start_line and line_num < start_line:
                continue
            if len(row) >= 2:
                rank = row[0].strip()
                domain = row[1].strip()
                if domain:
                    domains.append({
                        "rank": rank,
                        "domain": domain
                    })
                    if max_domains and len(domains) >= max_domains:
                        break
    return domains


def fetch_homepage(domain: str) -> Optional[Dict]:
    """
    获取域名主页内容
    
    Args:
        domain: 域名
        
    Returns:
        包含页面内容的字典，如果失败返回 None
    """
    urls = [
        f"https://{domain}",
        f"http://{domain}"
    ]
    
    for url in urls:
        try:
            response = requests.get(
                url,
                headers=REQUEST_HEADERS,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True,
                verify=False  # 忽略 SSL 证书验证
            )
            
            # 检查状态码
            if response.status_code == 200:
                # 正确检测和设置编码
                if response.encoding is None or response.encoding == 'ISO-8859-1':
                    # 尝试从 Content-Type 头获取编码
                    content_type = response.headers.get("Content-Type", "")
                    if 'charset=' in content_type:
                        try:
                            charset = content_type.split('charset=')[1].split(';')[0].strip().strip('"\'')
                            response.encoding = charset
                        except:
                            pass
                    
                    # 如果还是无法确定，尝试常见编码
                    if response.encoding is None or response.encoding == 'ISO-8859-1':
                        # 尝试检测编码
                        try:
                            import chardet
                            detected = chardet.detect(response.content)
                            if detected and detected.get('encoding'):
                                response.encoding = detected['encoding']
                            else:
                                response.encoding = 'utf-8'
                        except ImportError:
                            # chardet 未安装，默认使用 UTF-8
                            response.encoding = 'utf-8'
                
                # 获取文本内容，确保是 UTF-8
                try:
                    content = response.text
                    # 如果文本包含无法解码的字符，尝试重新编码
                    if not isinstance(content, str):
                        content = str(content, encoding='utf-8', errors='replace')
                except UnicodeDecodeError:
                    # 如果解码失败，尝试使用 errors='replace' 或 errors='ignore'
                    content = response.content.decode('utf-8', errors='replace')
                except Exception:
                    # 最后尝试：先解码为字节，再尝试常见编码
                    try:
                        content = response.content.decode('utf-8', errors='replace')
                    except:
                        content = response.content.decode('latin-1', errors='replace')
                
                # 清理内容：移除控制字符，但保留换行符和制表符
                import re
                content = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', content)
                
                # 限制内容长度
                original_length = len(content)
                if len(content) > DEFAULT_MAX_CONTENT_LENGTH:
                    content = content[:DEFAULT_MAX_CONTENT_LENGTH] + "\n[内容已截断...]"
                
                # 获取响应体前50个字符，用于检查编码问题
                content_preview = content[:50] if content else ""
                
                return {
                    "url": url,
                    "status_code": response.status_code,
                    "content": content,
                    "content_length": original_length,
                    "content_type": response.headers.get("Content-Type", ""),
                    "title": extract_title(content),
                    "content_preview": content_preview  # 响应体前50个字符，用于检查编码
                }
        except requests.exceptions.SSLError:
            # SSL 错误，尝试下一个 URL
            continue
        except requests.exceptions.Timeout:
            # 超时，尝试下一个 URL
            continue
        except requests.exceptions.RequestException as e:
            # 其他请求错误，尝试下一个 URL
            continue
        except Exception as e:
            # 其他异常（可能是编码问题）
            print(f"[!] 处理响应时出错: {e}")
            continue
    
    return None


def extract_title(content: str) -> str:
    """从 HTML 内容中提取标题"""
    import re
    import html
    
    # 尝试提取 <title> 标签
    title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
    if title_match:
        title = title_match.group(1).strip()
        # 解码 HTML 实体（如 &amp; 等）
        try:
            title = html.unescape(title)
        except:
            pass
        return title
    
    # 尝试提取 <h1> 标签
    h1_match = re.search(r'<h1[^>]*>([^<]+)</h1>', content, re.IGNORECASE)
    if h1_match:
        title = h1_match.group(1).strip()
        # 解码 HTML 实体
        try:
            title = html.unescape(title)
        except:
            pass
        return title
    
    return ""


def analyze_webrtc_with_ai(domain: str, page_content: Dict, api_key: str, model: str) -> Optional[Dict]:
    """
    使用 AI 模型分析页面内容，判断是否包含 WebRTC 相关服务
    
    Args:
        domain: 域名
        page_content: 页面内容字典
        api_key: OpenRouter API Key
        model: 模型名称
        
    Returns:
        AI 分析结果，包含判断和原因
    """
    if not api_key:
        print("[!] 错误: 未设置 OPENROUTER_API_KEY")
        return None
    
    # 清理页面内容，确保编码正确
    content = page_content.get('content', '')
    title = page_content.get('title', '')
    
    # 确保所有字符串都是有效的 UTF-8
    if not isinstance(content, str):
        try:
            content = str(content, encoding='utf-8', errors='replace')
        except:
            content = str(content)
    
    if not isinstance(title, str):
        try:
            title = str(title, encoding='utf-8', errors='replace')
        except:
            title = str(title)
    
    # 限制内容长度，避免超出 API 限制
    if len(content) > DEFAULT_MAX_CONTENT_LENGTH:
        content = content[:DEFAULT_MAX_CONTENT_LENGTH]
    
    # 构建提示词
    prompt = f"""
你是一名精通前端与实时通信技术的分析专家。现在我将提供一个网站主页的 HTML 源码，请你判断该网站是否使用了 WebRTC（Web Real-Time Communication） 技术。
请你从 网站业务语义 进行分析，并按以下步骤输出结果。

从页面的标题、描述，响应体内容的文字、注释或脚本变量命名中，推断网站的业务类型。
若网站功能与以下任意场景相关，则可能使用 WebRTC：

（1）视频通信类场景

视频会议、在线会议室、多方会议、远程会议、视频通话、一对一视频聊天、视频面试、在线问诊、远程课堂、虚拟会议平台

（2）语音与聊天类场景

实时语音通话、语音聊天室、语音房间、语音匹配、语音客服、即时聊天、实时沟通、在线对讲

（3）社交与互动类场景

随机视频聊天、在线视频配对、实时约会、面对面通信、互动社交、视频见面

（4）协作与远程操作类场景

屏幕共享、远程协作、在线演示、多人白板、在线办公、远程控制、在线辅导

（5）媒体与直播类场景

实时直播、低延迟推流、互动直播、视频客服、虚拟前台、远程展示、实时媒体播放

若源码中出现这些功能描述或提示性词汇，可判定该网站具备 WebRTC 通信能力。

3. 输出格式

综合上述分析，输出一个结构化 JSON：
{{
  "webrtc_usage": "确定使用 | 可能使用 | 未发现使用",
  "evidence": ["关键词或API片段1", "业务语义线索2", "接口路径3"],
  "reasoning": "简要说明推理过程"
}}


以下是网站 HTML 源码

域名: {domain}
URL: {page_content['url']}
状态码: {page_content['status_code']}
内容类型: {page_content['content_type']}
标题: {title}

页面内容:
{content}

"""
    
    # 确保 prompt 是有效的 UTF-8 字符串
    if not isinstance(prompt, str):
        prompt = str(prompt, encoding='utf-8', errors='replace')

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/turn-client",  # OpenRouter API 要求的头部
        "X-Title": "WebRTC Domain Scanner"  # OpenRouter API 要求的头部
    }
    
    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "stream": True,
        "temperature": AI_TEMPERATURE
    }
    
    try:
        response = requests.post(
            OPENROUTER_API_URL,
            headers=headers,
            json=payload,
            stream=True,
            timeout=AI_STREAM_TIMEOUT
        )
        
        # 检查初始状态码
        if response.status_code != 200:
            try:
                error_data = response.json()
                print(f"[!] API 错误: {error_data.get('error', {}).get('message', 'Unknown error')}")
            except:
                print(f"[!] API 错误: HTTP {response.status_code}")
            return None
        
        # 处理流式响应
        buffer = ""
        full_content = ""
        
        # 设置响应编码为 UTF-8
        response.encoding = 'utf-8'
        
        for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
            if interrupted:
                break
            
            # 确保 chunk 是字符串类型
            if isinstance(chunk, bytes):
                try:
                    chunk = chunk.decode('utf-8', errors='replace')
                except:
                    chunk = chunk.decode('latin-1', errors='replace')
                
            buffer += chunk
            
            while True:
                # 查找完整的 SSE 行
                line_end = buffer.find('\n')
                if line_end == -1:
                    break
                
                line = buffer[:line_end].strip()
                buffer = buffer[line_end + 1:]
                
                if line.startswith('data: '):
                    data = line[6:]
                    if data == '[DONE]':
                        break
                    
                    try:
                        data_obj = json.loads(data)
                        
                        # 检查是否有错误
                        if 'error' in data_obj:
                            error_msg = data_obj['error'].get('message', 'Unknown error')
                            # 确保错误消息是 UTF-8 编码
                            if isinstance(error_msg, bytes):
                                error_msg = error_msg.decode('utf-8', errors='replace')
                            print(f"[!] 流式响应错误: {error_msg}")
                            return None
                        
                        # 提取内容
                        delta = data_obj.get('choices', [{}])[0].get('delta', {})
                        content = delta.get('content', '')
                        if content:
                            # 确保内容是字符串类型
                            if isinstance(content, bytes):
                                content = content.decode('utf-8', errors='replace')
                            full_content += content
                            print(content, end='', flush=True)
                            
                        # 检查 finish_reason
                        finish_reason = data_obj.get('choices', [{}])[0].get('finish_reason')
                        if finish_reason == 'error':
                            print("\n[!] 流式响应因错误终止")
                            return None
                            
                    except json.JSONDecodeError as e:
                        # JSON 解析错误，跳过这行
                        pass
                    except UnicodeDecodeError:
                        # 编码错误，跳过这行
                        pass
        
        print()  # 换行
        
        # 尝试从完整内容中提取 JSON
        try:
            # 查找 JSON 对象
            json_start = full_content.find('{')
            json_end = full_content.rfind('}') + 1
            if json_start != -1 and json_end > json_start:
                json_str = full_content[json_start:json_end]
                result = json.loads(json_str)
                return result
            else:
                # 如果没有找到 JSON，返回原始内容
                return {
                    "webrtc_usage": "未发现使用",
                    "evidence": [],
                    "reasoning": "无法解析 AI 响应",
                    "raw_response": full_content
                }
        except json.JSONDecodeError:
            return {
                "webrtc_usage": "未发现使用",
                "evidence": [],
                "reasoning": "AI 响应格式错误",
                "raw_response": full_content
            }
            
    except requests.exceptions.RequestException as e:
        print(f"[!] API 请求失败: {e}")
        return None


def analyze_webrtc_initiation(domain: str, page_content: Dict, api_key: str, model: str) -> Optional[Dict]:
    """
    使用 AI 模型分析页面内容，判断是否可以从网站直接发起 WebRTC 通信
    
    Args:
        domain: 域名
        page_content: 页面内容字典
        api_key: OpenRouter API Key
        model: 模型名称
        
    Returns:
        AI 分析结果，包含是否可以发起 WebRTC 通信的判断
    """
    if not api_key:
        return None
    
    # 清理页面内容，确保编码正确
    content = page_content.get('content', '')
    title = page_content.get('title', '')
    
    # 确保所有字符串都是有效的 UTF-8
    if not isinstance(content, str):
        try:
            content = str(content, encoding='utf-8', errors='replace')
        except:
            content = str(content)
    
    if not isinstance(title, str):
        try:
            title = str(title, encoding='utf-8', errors='replace')
        except:
            title = str(title)
    
    # 限制内容长度，避免超出 API 限制
    if len(content) > DEFAULT_MAX_CONTENT_LENGTH:
        content = content[:DEFAULT_MAX_CONTENT_LENGTH]
    
    # 构建提示词
    prompt = f"""
你是一名精通前端与实时通信技术的分析专家。现在需要你判断该网站是否支持从网页直接发起 WebRTC 通信（无需下载软件或联系工作人员）。

请仔细分析以下 HTML 源码，查找以下关键证据：

1. 明确的发起通信按钮或组件
查找以下按钮文字、链接或组件：
- "立即开始"、"开始会议"、"加入会议"、"立即加入"、"开始通话"、"发起会议"、"创建会议"
- "Try Now"、"Start Meeting"、"Join Meeting"、"Start Demo"、"Try Demo"、"立即体验"、"免费试用"
- "视频通话"、"语音通话"、"屏幕共享"、"开始共享"、"开始演示"
- 查找 button、a、input[type="button"] 等元素，以及相关的 onclick、href 属性

2. 在线演示或 Demo 功能
查找以下线索：
- "Demo"、"演示"、"试用"、"体验"、"在线试用"、"在线演示"
- iframe 嵌入的通信组件
- 可以直接点击启动的演示功能

3. 需要额外步骤的情况
如果发现以下情况，应判定为"可能较小"：
- "下载应用"、"下载软件"、"Download"、"Install"、"获取应用"
- "联系销售"、"联系客服"、"Contact Sales"、"Schedule a Demo"
- "申请试用"、"申请演示"、"Request Demo" 等需要人工介入的步骤
- 页面仅提供产品介绍，没有直接发起通信的功能

4. 输出格式

请以 JSON 格式返回结果：
{{
    "can_initiate": "可行"/"可能较大"/"可能较小",
    "confidence": "high/medium/low",
    "reasons": ["原因1", "原因2", ...],
    "buttons_or_components_found": ["发现的按钮或组件1", "发现的按钮或组件2", ...],
    "requires_additional_steps": true/false,
    "additional_steps": ["需要下载软件", "需要联系销售"]  // 如果有额外步骤，列出具体步骤
}}

以下是网站 HTML 源码

域名: {domain}
URL: {page_content['url']}
标题: {title}

页面内容:
{content}
"""
    
    # 确保 prompt 是有效的 UTF-8 字符串
    if not isinstance(prompt, str):
        prompt = str(prompt, encoding='utf-8', errors='replace')

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/turn-client",  # OpenRouter API 要求的头部
        "X-Title": "WebRTC Domain Scanner"  # OpenRouter API 要求的头部
    }
    
    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "stream": True,
        "temperature": AI_TEMPERATURE
    }
    
    try:
        response = requests.post(
            OPENROUTER_API_URL,
            headers=headers,
            json=payload,
            stream=True,
            timeout=AI_STREAM_TIMEOUT
        )
        
        # 检查初始状态码
        if response.status_code != 200:
            try:
                error_data = response.json()
                print(f"[!] API 错误: {error_data.get('error', {}).get('message', 'Unknown error')}")
            except:
                print(f"[!] API 错误: HTTP {response.status_code}")
            return None
        
        # 处理流式响应
        buffer = ""
        full_content = ""
        
        # 设置响应编码为 UTF-8
        response.encoding = 'utf-8'
        
        for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
            if interrupted:
                break
            
            # 确保 chunk 是字符串类型
            if isinstance(chunk, bytes):
                try:
                    chunk = chunk.decode('utf-8', errors='replace')
                except:
                    chunk = chunk.decode('latin-1', errors='replace')
                
            buffer += chunk
            
            while True:
                # 查找完整的 SSE 行
                line_end = buffer.find('\n')
                if line_end == -1:
                    break
                
                line = buffer[:line_end].strip()
                buffer = buffer[line_end + 1:]
                
                if line.startswith('data: '):
                    data = line[6:]
                    if data == '[DONE]':
                        break
                    
                    try:
                        data_obj = json.loads(data)
                        
                        # 检查是否有错误
                        if 'error' in data_obj:
                            error_msg = data_obj['error'].get('message', 'Unknown error')
                            # 确保错误消息是 UTF-8 编码
                            if isinstance(error_msg, bytes):
                                error_msg = error_msg.decode('utf-8', errors='replace')
                            print(f"[!] 流式响应错误: {error_msg}")
                            return None
                        
                        # 提取内容
                        delta = data_obj.get('choices', [{}])[0].get('delta', {})
                        content = delta.get('content', '')
                        if content:
                            # 确保内容是字符串类型
                            if isinstance(content, bytes):
                                content = content.decode('utf-8', errors='replace')
                            full_content += content
                            print(content, end='', flush=True)
                            
                        # 检查 finish_reason
                        finish_reason = data_obj.get('choices', [{}])[0].get('finish_reason')
                        if finish_reason == 'error':
                            print("\n[!] 流式响应因错误终止")
                            return None
                            
                    except json.JSONDecodeError as e:
                        # JSON 解析错误，跳过这行
                        pass
                    except UnicodeDecodeError:
                        # 编码错误，跳过这行
                        pass
        
        print()  # 换行
        
        # 尝试从完整内容中提取 JSON
        try:
            # 查找 JSON 对象
            json_start = full_content.find('{')
            json_end = full_content.rfind('}') + 1
            if json_start != -1 and json_end > json_start:
                json_str = full_content[json_start:json_end]
                result = json.loads(json_str)
                return result
            else:
                # 如果没有找到 JSON，返回原始内容
                return {
                    "can_initiate": "unknown",
                    "confidence": "unknown",
                    "reasons": ["无法解析 AI 响应"],
                    "raw_response": full_content
                }
        except json.JSONDecodeError:
            return {
                "can_initiate": "unknown",
                "confidence": "unknown",
                "reasons": ["AI 响应格式错误"],
                "raw_response": full_content
            }
            
    except requests.exceptions.RequestException as e:
        print(f"[!] API 请求失败: {e}")
        return None


def save_progress(current_line: int, results: List[Dict]):
    """保存进度和结果（线程安全）"""
    with file_lock:
        progress = {
            "last_line": current_line,
            "timestamp": datetime.now().isoformat(),
            "total_processed": len(results)
        }
        
        with open(PROGRESS_FILE, 'w', encoding='utf-8') as f:
            json.dump(progress, f, indent=2, ensure_ascii=False)
        
        with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)


def load_progress() -> int:
    """加载上次的进度（线程安全）"""
    with file_lock:
        if os.path.exists(PROGRESS_FILE):
            with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
                progress = json.load(f)
                return progress.get("last_line", 1)
    return 1


def load_results() -> List[Dict]:
    """加载已有结果（线程安全）"""
    with file_lock:
        results = []
        if os.path.exists(RESULTS_FILE):
            with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
                results = json.load(f)
        return results


def process_domain(domain_info: Dict, start_line: int, api_key: str, model: str, delay: float, thread_id: int, num_threads: int) -> Optional[Dict]:
    """
    处理单个域名（线程安全）
    
    Args:
        domain_info: 域名信息字典，包含 rank 和 domain
        start_line: 起始行号
        api_key: OpenRouter API Key
        model: 模型名称
        delay: 延迟时间
        thread_id: 线程ID（1-based）
        num_threads: 线程总数
        
    Returns:
        处理结果字典，如果已处理或出错则返回 None
    """
    rank = domain_info["rank"]
    domain = domain_info["domain"]
    
    # 根据 rank % num_threads == thread_id - 1 判断是否由当前线程处理
    if rank % num_threads != thread_id - 1:
        return None  # 不属于当前线程处理
    
    # 加载已有结果并检查是否已处理
    results = load_results()
    already_processed = any(
        r.get("rank") == rank and r.get("domain") == domain
        for r in results
    )
    
    if already_processed:
        print(f"[线程 {thread_id}] 域名 {domain} (排名: {rank}) 已处理过，跳过")
        return None
    
    print(f"[线程 {thread_id}] 处理域名: {domain} (排名: {rank})")
    
    # 获取主页内容
    print(f"[线程 {thread_id}] 获取主页内容...")
    page_content = fetch_homepage(domain)
    
    if not page_content:
        print(f"[线程 {thread_id}] 无法获取主页内容")
        result = {
            "rank": rank,
            "domain": domain,
            "line": start_line + rank - 1,  # 估算行号
            "timestamp": datetime.now().isoformat(),
            "status": "failed",
            "error": "无法获取主页内容",
            "thread_id": thread_id
        }
        
        # 线程安全地保存结果
        with results_lock:
            results = load_results()
            results.append(result)
            save_progress(start_line + rank - 1, results)
        
        time.sleep(delay)
        return result
    
    print(f"[线程 {thread_id}] 成功获取主页内容 ({page_content['content_length']} 字符)")
    print(f"[线程 {thread_id}] URL: {page_content['url']}")
    print(f"[线程 {thread_id}] 标题: {page_content['title']}")
    
    # 两阶段 AI 分析：先用快速模型，如果结果是"可能使用"则用更准确的模型重新判断
    print(f"[线程 {thread_id}] 第一阶段：使用快速模型 (google/gemini-2.0-flash-001) 分析 WebRTC 服务...")
    ai_result = analyze_webrtc_with_ai(domain, page_content, api_key, "google/gemini-2.0-flash-001")
    
    # 如果第一次判断结果是"可能使用"，使用更准确的模型重新判断
    if ai_result and ai_result.get("webrtc_usage") == "可能使用":
        print(f"[线程 {thread_id}] 第一阶段结果为'可能使用'，使用更准确模型 (google/gemini-2.5-pro) 重新判断...")
        second_result = analyze_webrtc_with_ai(domain, page_content, api_key, "google/gemini-2.5-pro")
        if second_result:
            # 以第二次判断的结果为准
            ai_result = second_result
            print(f"[线程 {thread_id}] 第二阶段判断完成，以本次结果为准")
        else:
            print(f"[线程 {thread_id}] 第二阶段判断失败，使用第一阶段结果")
    
    if ai_result:
        # 解析新的 JSON 格式
        webrtc_usage = ai_result.get("webrtc_usage", "未发现使用")
        evidence = ai_result.get("evidence", [])
        reasoning = ai_result.get("reasoning", "")
        
        # 将 webrtc_usage 转换为布尔值
        has_webrtc = webrtc_usage in ["确定使用", "可能使用"]
        
        # 根据 webrtc_usage 确定置信度
        if webrtc_usage == "确定使用":
            confidence = "high"
        elif webrtc_usage == "可能使用":
            confidence = "medium"
        else:
            confidence = "low"
        
        print(f"[线程 {thread_id}] AI 分析结果:")
        print(f"[线程 {thread_id}]   WebRTC 使用情况: {webrtc_usage}")
        print(f"[线程 {thread_id}]   置信度: {confidence}")
        
        # 如果判断存在 WebRTC 服务，进一步判断是否可以从网站发起通信
        initiation_analysis = None
        if has_webrtc:
            # 使用更准确的模型进行发起通信能力分析
            print(f"[线程 {thread_id}] 检测到 WebRTC 服务，进一步分析是否可从网站发起通信...")
            initiation_analysis = analyze_webrtc_initiation(domain, page_content, api_key, "google/gemini-2.5-pro")
            
            if initiation_analysis:
                can_initiate = initiation_analysis.get("can_initiate", "unknown")
                print(f"[线程 {thread_id}] 发起通信能力: {can_initiate}")
        
        result = {
            "rank": rank,
            "domain": domain,
            "line": start_line + rank - 1,  # 估算行号
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "thread_id": thread_id,
            "page_info": {
                "url": page_content["url"],
                "status_code": page_content["status_code"],
                "content_type": page_content["content_type"],
                "title": page_content["title"],
                "content_length": page_content["content_length"],
                "content_preview": page_content.get("content_preview", "")
            },
            "ai_analysis": {
                "webrtc_usage": webrtc_usage,
                "has_webrtc": has_webrtc,
                "confidence": confidence,
                "evidence": evidence,
                "reasoning": reasoning,
                "initiation_analysis": initiation_analysis
            }
        }
    else:
        print(f"[线程 {thread_id}] AI 分析失败")
        result = {
            "rank": rank,
            "domain": domain,
            "line": start_line + rank - 1,  # 估算行号
            "timestamp": datetime.now().isoformat(),
            "status": "ai_failed",
            "thread_id": thread_id,
            "page_info": {
                "url": page_content["url"],
                "status_code": page_content["status_code"],
                "content_type": page_content["content_type"],
                "title": page_content["title"],
                "content_length": page_content["content_length"],
                "content_preview": page_content.get("content_preview", "")
            },
            "error": "AI 分析失败"
        }
    
    # 线程安全地保存结果
    with results_lock:
        results = load_results()
        results.append(result)
        save_progress(start_line + rank - 1, results)
    
    # 延迟
    time.sleep(delay)
    
    return result


def main():
    # 验证配置
    is_valid, error = validate_config()
    if not is_valid:
        print(f"[!] 配置错误: {error}")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="扫描域名列表，使用 AI 判断是否包含 WebRTC 相关服务"
    )
    parser.add_argument(
        "--csv",
        default=DEFAULT_CSV_FILE,
        help=f"CSV 文件路径（默认: {DEFAULT_CSV_FILE}）"
    )
    parser.add_argument(
        "--start",
        type=int,
        help="从第几行开始（1-based）"
    )
    parser.add_argument(
        "--max",
        type=int,
        help="最多处理多少个域名"
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"OpenRouter 模型名称（默认: {DEFAULT_MODEL}）"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=f"请求之间的延迟（秒，默认: {DEFAULT_DELAY}）"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="从上次停止的位置继续"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="线程数量（默认: 1，单线程模式）"
    )
    
    args = parser.parse_args()
    
    # 获取 API Key
    api_key = get_api_key()
    if not api_key:
        print("[!] 错误: 请设置 OPENROUTER_API_KEY 环境变量或修改配置文件")
        print("    方式1: export OPENROUTER_API_KEY='your-api-key'")
        print("    方式2: 编辑 webrtc_domain_scanner_config.py 文件")
        sys.exit(1)
    
    # 确定起始行
    start_line = args.start
    if args.resume and not start_line:
        start_line = load_progress()
        if start_line > 1:
            print(f"[+] 从上次停止的位置继续: 第 {start_line} 行")
    
    # 读取域名列表
    print(f"[+] 读取域名列表: {args.csv}")
    domains = read_domains(args.csv, start_line=start_line, max_domains=args.max)
    
    if not domains:
        print("[!] 没有找到域名")
        return
    
    print(f"[+] 找到 {len(domains)} 个域名待处理")
    print(f"[+] 使用模型: {args.model}")
    print(f"[+] API Key: {'已设置' if api_key else '未设置'}")
    print(f"[+] 线程数量: {args.threads}")
    
    # 多线程处理
    if args.threads > 1:
        print(f"[+] 使用 {args.threads} 个线程处理域名")
        print(f"[+] 分配规则: 第 i 个线程处理 rank % {args.threads} == i-1 的域名")
        
        # 定义包装函数，根据 rank 自动分配线程ID
        def process_domain_wrapper(domain_info: Dict):
            """包装函数，根据 rank 自动计算线程ID"""
            rank = domain_info["rank"]
            # 计算线程ID：rank % num_threads 的结果是 0 到 num_threads-1，加1得到1-based的线程ID
            thread_id = (rank % args.threads) + 1
            return process_domain(
                domain_info,
                start_line or 1,
                api_key,
                args.model,
                args.delay,
                thread_id,
                args.threads
            )
        
        # 使用线程池处理
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            
            for domain_info in domains:
                if interrupted:
                    print("\n[!] 已中断，等待线程完成...")
                    break
                
                # 提交任务（包装函数会自动分配线程ID）
                future = executor.submit(process_domain_wrapper, domain_info)
                futures.append(future)
            
            # 等待所有任务完成
            completed = 0
            for future in as_completed(futures):
                if interrupted:
                    print("[!] 中断信号已接收，等待当前任务完成...")
                    break
                try:
                    result = future.result()
                    if result:
                        completed += 1
                except Exception as e:
                    print(f"[!] 处理域名时出错: {e}")
            
            # 中断后保存最终进度
            if interrupted:
                try:
                    results = load_results()
                    if results:
                        last_line = max((r.get("line", 0) for r in results), default=start_line or 1)
                        save_progress(last_line, results)
                        print(f"[+] 进度已保存，最后处理的行号: {last_line}")
                except Exception as e:
                    print(f"[!] 保存进度时出错: {e}")
            
            print(f"[+] 线程池处理完成，共处理 {completed} 个域名")
    else:
        # 单线程处理（保持原有逻辑）
        print(f"[+] 使用单线程模式")
        
        # 加载已有结果
        results = load_results()
        
        # 处理每个域名
        for i, domain_info in enumerate(domains, start=1):
            if interrupted:
                print("\n[!] 已中断，保存进度...")
                # 确保保存当前进度
                try:
                    if results:
                        last_line = max((r.get("line", 0) for r in results), default=start_line or 1)
                        save_progress(last_line, results)
                        print(f"[+] 进度已保存，最后处理的行号: {last_line}")
                except Exception as e:
                    print(f"[!] 保存进度时出错: {e}")
                break
            
            rank = domain_info["rank"]
            domain = domain_info["domain"]
            current_line = (start_line or 1) + i - 1
            
            print(f"\n[{i}/{len(domains)}] 处理域名: {domain} (排名: {rank}, 行号: {current_line})")
            
            # 检查是否已处理
            already_processed = any(
                r.get("rank") == rank and r.get("domain") == domain
                for r in results
            )
            
            if already_processed:
                print(f"[*] 已处理过，跳过")
                continue
            
            # 获取主页内容
            print(f"[*] 获取主页内容...")
            page_content = fetch_homepage(domain)
            
            if not page_content:
                print(f"[!] 无法获取主页内容")
                result = {
                    "rank": rank,
                    "domain": domain,
                    "line": current_line,
                    "timestamp": datetime.now().isoformat(),
                    "status": "failed",
                    "error": "无法获取主页内容"
                }
                results.append(result)
                save_progress(current_line, results)
                time.sleep(args.delay)
                continue
            
            print(f"[+] 成功获取主页内容 ({page_content['content_length']} 字符)")
            print(f"    URL: {page_content['url']}")
            print(f"    标题: {page_content['title']}")
            print(f"    内容预览: {repr(page_content.get('content_preview', ''))}")
            
            # 两阶段 AI 分析：先用快速模型，如果结果是"可能使用"则用更准确的模型重新判断
            print(f"[*] 第一阶段：使用快速模型 (google/gemini-2.0-flash-001) 分析 WebRTC 服务...")
            ai_result = analyze_webrtc_with_ai(domain, page_content, api_key, "google/gemini-2.0-flash-001")
            
            # 如果第一次判断结果是"可能使用"，使用更准确的模型重新判断
            if ai_result and ai_result.get("webrtc_usage") == "可能使用":
                print(f"[*] 第一阶段结果为'可能使用'，使用更准确模型 (google/gemini-2.5-pro) 重新判断...")
                second_result = analyze_webrtc_with_ai(domain, page_content, api_key, "google/gemini-2.5-pro")
                if second_result:
                    # 以第二次判断的结果为准
                    ai_result = second_result
                    print(f"[+] 第二阶段判断完成，以本次结果为准")
                else:
                    print(f"[!] 第二阶段判断失败，使用第一阶段结果")
            
            if ai_result:
                # 解析新的 JSON 格式
                webrtc_usage = ai_result.get("webrtc_usage", "未发现使用")
                evidence = ai_result.get("evidence", [])
                reasoning = ai_result.get("reasoning", "")
                
                # 将 webrtc_usage 转换为布尔值
                has_webrtc = webrtc_usage in ["确定使用", "可能使用"]
                
                # 根据 webrtc_usage 确定置信度
                if webrtc_usage == "确定使用":
                    confidence = "high"
                elif webrtc_usage == "可能使用":
                    confidence = "medium"
                else:
                    confidence = "low"
                
                print(f"[+] AI 分析结果:")
                print(f"    WebRTC 使用情况: {webrtc_usage}")
                print(f"    置信度: {confidence}")
                if evidence:
                    print(f"    证据: {', '.join(evidence[:5])}")
                if reasoning:
                    print(f"    推理: {reasoning[:200]}...")
                
                # 如果判断存在 WebRTC 服务，进一步判断是否可以从网站发起通信
                initiation_analysis = None
                if has_webrtc:
                    # 使用更准确的模型进行发起通信能力分析
                    print(f"[*] 检测到 WebRTC 服务，进一步分析是否可从网站发起通信...")
                    initiation_analysis = analyze_webrtc_initiation(domain, page_content, api_key, "google/gemini-2.5-pro")
                    
                    if initiation_analysis:
                        can_initiate = initiation_analysis.get("can_initiate", "unknown")
                        print(f"[+] 发起通信能力: {can_initiate}")
                
                result = {
                    "rank": rank,
                    "domain": domain,
                    "line": current_line,
                    "timestamp": datetime.now().isoformat(),
                    "status": "success",
                    "page_info": {
                        "url": page_content["url"],
                        "status_code": page_content["status_code"],
                        "content_type": page_content["content_type"],
                        "title": page_content["title"],
                        "content_length": page_content["content_length"],
                        "content_preview": page_content.get("content_preview", "")
                    },
                    "ai_analysis": {
                        "webrtc_usage": webrtc_usage,
                        "has_webrtc": has_webrtc,
                        "confidence": confidence,
                        "evidence": evidence,
                        "reasoning": reasoning,
                        "initiation_analysis": initiation_analysis
                    }
                }
            else:
                print(f"[!] AI 分析失败")
                result = {
                    "rank": rank,
                    "domain": domain,
                    "line": current_line,
                    "timestamp": datetime.now().isoformat(),
                    "status": "ai_failed",
                    "page_info": {
                        "url": page_content["url"],
                        "status_code": page_content["status_code"],
                        "content_type": page_content["content_type"],
                        "title": page_content["title"],
                        "content_length": page_content["content_length"],
                        "content_preview": page_content.get("content_preview", "")
                    },
                    "error": "AI 分析失败"
                }
            
            results.append(result)
            save_progress(current_line, results)
            
            # 延迟
            if i < len(domains):
                time.sleep(args.delay)
        
        # 保存最终结果
        save_progress(start_line + len(domains) if start_line else len(domains), results)
    
    # 加载最终结果用于统计
    results = load_results()
    
    # 统计结果
    print("\n" + "="*60)
    print("📊 扫描完成统计")
    print("="*60)
    total = len(results)
    success = sum(1 for r in results if r.get("status") == "success")
    failed = sum(1 for r in results if r.get("status") == "failed")
    ai_failed = sum(1 for r in results if r.get("status") == "ai_failed")
    has_webrtc = sum(1 for r in results 
                    if r.get("status") == "success" 
                    and r.get("ai_analysis", {}).get("has_webrtc") is True)
    
    # 统计新格式的使用情况
    definitely_uses = sum(1 for r in results 
                         if r.get("status") == "success"
                         and r.get("ai_analysis", {}).get("webrtc_usage") == "确定使用")
    possibly_uses = sum(1 for r in results 
                       if r.get("status") == "success"
                       and r.get("ai_analysis", {}).get("webrtc_usage") == "可能使用")
    
    print(f"总计: {total}")
    print(f"成功: {success}")
    print(f"失败: {failed}")
    print(f"AI 分析失败: {ai_failed}")
    print(f"包含 WebRTC: {has_webrtc}")
    print(f"  确定使用: {definitely_uses}")
    print(f"  可能使用: {possibly_uses}")
    print(f"\n结果已保存到: {RESULTS_FILE}")


if __name__ == "__main__":
    # 禁用 SSL 警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()

