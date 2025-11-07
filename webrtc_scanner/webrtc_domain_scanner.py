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
    RESULTS_FILE_PREFIX,
    RESULTS_FILE_SUFFIX,
    PROGRESS_FILE,
    BATCH_SIZE,
    validate_config
)

# 导入页面元素提取器
from page_element_extractor import (
    fetch_and_extract_elements,
    format_elements_for_ai
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
        域名列表，每个元素包含 rank、domain 和 line（实际行号）
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
                        "domain": domain,
                        "line": line_num  # 记录实际行号
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


def analyze_webrtc_with_ai(domain: str, elements_data: Dict, api_key: str, model: str) -> Optional[Dict]:
    """
    使用 AI 模型分析页面元素，判断是否包含 WebRTC 相关服务
    
    Args:
        domain: 域名
        elements_data: 包含提取元素的页面数据字典
        api_key: OpenRouter API Key
        model: 模型名称
        
    Returns:
        AI 分析结果，包含判断和原因
    """
    if not api_key:
        print("[!] 错误: 未设置 OPENROUTER_API_KEY")
        return None
    
    # 格式化元素信息用于 AI 分析
    elements_text = format_elements_for_ai(elements_data)
    elements_text_length = len(elements_text)
    print(f"[*] 提取的元素信息长度: {elements_text_length} 字符")
    title = elements_data.get('title', '')
    
    # 确保所有字符串都是有效的 UTF-8
    if not isinstance(elements_text, str):
        try:
            elements_text = str(elements_text, encoding='utf-8', errors='replace')
        except:
            elements_text = str(elements_text)
    
    if not isinstance(title, str):
        try:
            title = str(title, encoding='utf-8', errors='replace')
        except:
            title = str(title)
    
    # 构建提示词
    prompt = f"""
你是一名精通前端与实时通信技术的分析专家。现在我将提供一个网站主页的页面元素信息（包括按钮、链接、输入框的文本和属性），请你判断该网站是否使用了 WebRTC（Web Real-Time Communication） 技术。
请你从 网站业务语义 进行分析，并按以下步骤输出结果。

从页面的标题、按钮文本、链接文本、输入框的 placeholder 或 value 等元素中，推断网站的业务类型。
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

若页面元素中出现这些功能描述或提示性词汇，可判定该网站具备 WebRTC 通信能力。

3. 输出格式

综合上述分析，输出一个结构化 JSON：
{{
  "webrtc_usage": "确定使用 | 可能使用 | 未发现使用",
  "evidence": ["关键词或API片段1", "业务语义线索2", "接口路径3"],
  "reasoning": "简要说明推理过程"
}}


以下是网站页面元素信息

域名: {domain}
URL: {elements_data['url']}
状态码: {elements_data['status_code']}
内容类型: {elements_data['content_type']}
标题: {title}

页面元素信息:
{elements_text}

"""
    
    # 确保 prompt 是有效的 UTF-8 字符串
    if not isinstance(prompt, str):
        prompt = str(prompt, encoding='utf-8', errors='replace')

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "stream": False,  # 使用非流式响应
        "temperature": AI_TEMPERATURE
    }
    
    try:
        response = requests.post(
            OPENROUTER_API_URL,
            headers=headers,
            json=payload,
            timeout=AI_STREAM_TIMEOUT
        )
        
        # 检查初始状态码
        if response.status_code != 200:
            try:
                error_data = response.json()
                error_msg = error_data.get('error', {})
                if isinstance(error_msg, dict):
                    error_msg = error_msg.get('message', str(error_msg))
                print(f"[!] API 错误: {error_msg}")
            except:
                print(f"[!] API 错误: HTTP {response.status_code}")
                print(f"[!] 响应内容: {response.text[:500]}")
            return None
        
        # 处理非流式响应
        try:
            response_data = response.json()
            
            # 检查是否有错误
            if 'error' in response_data:
                error_msg = response_data['error']
                if isinstance(error_msg, dict):
                    error_msg = error_msg.get('message', str(error_msg))
                print(f"[!] API 返回错误: {error_msg}")
                return None
            
            # 提取完整响应内容
            choices = response_data.get('choices', [])
            if not choices:
                print("[!] API 响应中没有 choices 字段")
                return None
            
            # 获取第一条消息的完整内容
            message = choices[0].get('message', {})
            full_content = message.get('content', '')
            
            if not full_content:
                print("[!] API 响应中没有内容")
                return None
            
            # 打印响应内容（用于调试）
            print(full_content)
            
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
                        "reasoning": "无法从响应中提取 JSON，原始响应：" + full_content[:200]
                    }
            except json.JSONDecodeError as e:
                return {
                    "webrtc_usage": "未发现使用",
                    "evidence": [],
                    "reasoning": f"AI 响应格式错误: {str(e)}",
                    "raw_response": full_content[:500]
                }
                
        except json.JSONDecodeError as e:
            print(f"[!] 无法解析 JSON 响应: {e}")
            print(f"[!] 响应内容: {response.text[:500]}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[!] API 请求失败: {e}")
        return None


def get_results_file_path(batch_number: int) -> str:
    """
    根据批次号生成结果文件路径
    
    Args:
        batch_number: 批次号（从1开始）
        
    Returns:
        结果文件路径
    """
    return f"{RESULTS_FILE_PREFIX}_{batch_number:04d}{RESULTS_FILE_SUFFIX}"


def save_progress(current_line: int, results: List[Dict]):
    """
    保存进度和结果（线程安全）
    每1000个域名保存到一个文件
    
    Args:
        current_line: 当前处理的行号（用于兼容，实际会从 results 中计算最大行号）
        results: 所有结果列表
    """
    with file_lock:
        # 计算当前批次号（从1开始）
        total_processed = len(results)
        current_batch = (total_processed - 1) // BATCH_SIZE + 1
        
        # 从结果中计算实际的最大行号
        if results:
            actual_last_line = max((r.get("line", 0) for r in results), default=current_line)
        else:
            actual_last_line = current_line
        
        # 保存进度信息
        progress = {
            "last_line": actual_last_line,  # 使用实际的最大行号
            "timestamp": datetime.now().isoformat(),
            "total_processed": total_processed,
            "current_batch": current_batch,
            "current_batch_size": total_processed % BATCH_SIZE if total_processed % BATCH_SIZE != 0 else BATCH_SIZE
        }
        
        with open(PROGRESS_FILE, 'w', encoding='utf-8') as f:
            json.dump(progress, f, indent=2, ensure_ascii=False)
        
        # 计算当前批次的结果
        batch_start = (current_batch - 1) * BATCH_SIZE
        batch_end = min(batch_start + BATCH_SIZE, total_processed)
        current_batch_results = results[batch_start:batch_end]
        
        # 保存当前批次的结果
        current_batch_file = get_results_file_path(current_batch)
        with open(current_batch_file, 'w', encoding='utf-8') as f:
            json.dump(current_batch_results, f, indent=2, ensure_ascii=False)
        
        # 如果当前批次已满，打印提示
        if len(current_batch_results) == BATCH_SIZE:
            print(f"[+] 批次 {current_batch} 已满（{BATCH_SIZE} 个域名），已保存到 {current_batch_file}")


def load_progress() -> int:
    """加载上次的进度（线程安全）"""
    with file_lock:
        if os.path.exists(PROGRESS_FILE):
            with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
                progress = json.load(f)
                return progress.get("last_line", 1)
    return 1


def load_results(verbose: bool = False) -> List[Dict]:
    """
    加载已有结果（线程安全）
    从所有批次文件中加载结果
    
    Args:
        verbose: 是否显示详细的加载信息
    """
    with file_lock:
        results = []
        
        # 首先检查进度文件，获取当前批次信息
        current_batch = 1
        if os.path.exists(PROGRESS_FILE):
            try:
                with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
                    progress = json.load(f)
                    current_batch = progress.get("current_batch", 1)
            except:
                pass
        
        # 兼容旧格式：如果存在旧的单文件格式，先加载它
        old_results_file = f"{RESULTS_FILE_PREFIX}{RESULTS_FILE_SUFFIX}"
        old_file_loaded = False
        
        # 检查是否已经存在批次文件
        first_batch_file = get_results_file_path(1)
        has_batch_files = os.path.exists(first_batch_file)
        
        if os.path.exists(old_results_file) and not has_batch_files:
            # 只有在没有批次文件时才转换旧文件
            try:
                with open(old_results_file, 'r', encoding='utf-8') as f:
                    old_results = json.load(f)
                    if old_results:
                        results.extend(old_results)
                        old_file_loaded = True
                        if verbose:
                            print(f"[*] 加载旧格式文件: {old_results_file} ({len(old_results)} 个结果)")
                        # 将旧文件转换为批次文件格式
                        if len(old_results) > 0:
                            batch_num = 1
                            for i in range(0, len(old_results), BATCH_SIZE):
                                batch_results = old_results[i:i+BATCH_SIZE]
                                batch_file = get_results_file_path(batch_num)
                                with open(batch_file, 'w', encoding='utf-8') as bf:
                                    json.dump(batch_results, bf, indent=2, ensure_ascii=False)
                                if verbose:
                                    print(f"[*] 转换旧文件到批次 {batch_num}: {batch_file} ({len(batch_results)} 个结果)")
                                batch_num += 1
                        # 备份旧文件
                        backup_file = f"{old_results_file}.backup"
                        if not os.path.exists(backup_file):
                            import shutil
                            shutil.copy2(old_results_file, backup_file)
                            if verbose:
                                print(f"[*] 旧文件已备份到: {backup_file}")
            except Exception as e:
                if verbose:
                    print(f"[!] 加载旧格式文件失败: {e}")
        
        # 加载所有已存在的批次文件
        # 如果已经从旧文件加载了，计算应该从哪个批次开始加载
        start_batch = 1
        if old_file_loaded and results:
            # 计算已加载的结果对应的批次数量
            loaded_batches = (len(results) - 1) // BATCH_SIZE + 1
            start_batch = loaded_batches + 1
        
        batch_num = start_batch
        while True:
            batch_file = get_results_file_path(batch_num)
            if os.path.exists(batch_file):
                try:
                    with open(batch_file, 'r', encoding='utf-8') as f:
                        batch_results = json.load(f)
                        results.extend(batch_results)
                        if verbose:
                            print(f"[*] 加载批次 {batch_num}: {len(batch_results)} 个结果")
                except Exception as e:
                    if verbose:
                        print(f"[!] 加载批次文件 {batch_file} 失败: {e}")
                batch_num += 1
            else:
                break
        
        return results


def process_domain(domain_info: Dict, start_line: int, api_key: str, model: str, delay: float, thread_id: int, num_threads: int) -> Optional[Dict]:
    """
    处理单个域名（线程安全）
    
    Args:
        domain_info: 域名信息字典，包含 rank、domain 和 line
        start_line: 起始行号（已废弃，保留用于兼容）
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
    actual_line = domain_info.get("line", start_line)  # 使用实际行号
    
    # 将 rank 转换为整数用于线程分配
    try:
        rank_int = int(rank)
    except (ValueError, TypeError):
        rank_int = hash(rank) % 1000000  # 如果 rank 不是数字，使用哈希值
    
    # 根据 rank % num_threads == thread_id - 1 判断是否由当前线程处理
    if rank_int % num_threads != thread_id - 1:
        return None  # 不属于当前线程处理
    
    # 加载已有结果并检查是否已处理
    results = load_results()
    already_processed = any(
        r.get("rank") == rank and r.get("domain") == domain
        for r in results
    )
    
    if already_processed:
        print(f"[线程 {thread_id}] 域名 {domain} (排名: {rank}, 行号: {actual_line}) 已处理过，跳过")
        return None
    
    print(f"[线程 {thread_id}] 处理域名: {domain} (排名: {rank}, 行号: {actual_line})")
    
    # 获取主页内容并提取元素
    print(f"[线程 {thread_id}] 获取主页内容并提取元素...")
    elements_data = fetch_and_extract_elements(domain)
    
    if not elements_data:
        print(f"[线程 {thread_id}] 无法获取主页内容")
        result = {
            "rank": rank,
            "domain": domain,
            "line": actual_line,  # 使用实际行号
            "timestamp": datetime.now().isoformat(),
            "status": "failed",
            "error": "无法获取主页内容",
            "thread_id": thread_id
        }
        
        # 线程安全地保存结果
        with results_lock:
            results = load_results()
            results.append(result)
            save_progress(actual_line, results)
        
        time.sleep(delay)
        return result
    
    print(f"[线程 {thread_id}] 成功获取主页内容并提取元素")
    print(f"[线程 {thread_id}] URL: {elements_data['url']}")
    print(f"[线程 {thread_id}] 标题: {elements_data['title']}")
    elements = elements_data.get('elements', {})
    print(f"[线程 {thread_id}] 提取的元素: {len(elements.get('buttons', []))} 个按钮, {len(elements.get('links', []))} 个链接, {len(elements.get('inputs', []))} 个输入框")
    
    # 两阶段 AI 分析：先用快速模型，如果出错或结果是"可能使用"则用更准确的模型重新判断
    print(f"[线程 {thread_id}] 第一阶段：使用快速模型 (gemini-2.0-flash-exp) 分析 WebRTC 服务...")
    ai_result = analyze_webrtc_with_ai(domain, elements_data, api_key, "gemini-2.0-flash-exp")
    
    # 如果第一次判断失败（返回 None），使用更准确的模型重新判断
    if not ai_result:
        print(f"[线程 {thread_id}] 第一阶段分析失败，使用更准确模型 (gemini-2.5-pro) 重新尝试...")
        ai_result = analyze_webrtc_with_ai(domain, elements_data, api_key, "gemini-2.5-pro")
        if ai_result:
            print(f"[线程 {thread_id}] 使用昂贵模型分析成功")
        else:
            print(f"[线程 {thread_id}] 昂贵模型分析也失败")
    # 如果第一次判断结果是"可能使用"，使用更准确的模型重新判断
    elif ai_result.get("webrtc_usage") == "可能使用":
        print(f"[线程 {thread_id}] 第一阶段结果为'可能使用'，使用更准确模型 (gemini-2.5-pro) 重新判断...")
        second_result = analyze_webrtc_with_ai(domain, elements_data, api_key, "gemini-2.5-pro")
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
        
        result = {
            "rank": rank,
            "domain": domain,
            "line": actual_line,  # 使用实际行号
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "thread_id": thread_id,
            "page_info": {
                "url": elements_data["url"],
                "status_code": elements_data["status_code"],
                "content_type": elements_data["content_type"],
                "title": elements_data["title"],
                "content_length": elements_data["content_length"],
                "content_preview": elements_data.get("content_preview", "")
            },
            "ai_analysis": {
                "webrtc_usage": webrtc_usage,
                "has_webrtc": has_webrtc,
                "confidence": confidence,
                "evidence": evidence,
                "reasoning": reasoning
            }
        }
    else:
        print(f"[线程 {thread_id}] AI 分析失败")
        result = {
            "rank": rank,
            "domain": domain,
            "line": actual_line,  # 使用实际行号
            "timestamp": datetime.now().isoformat(),
            "status": "ai_failed",
            "thread_id": thread_id,
            "page_info": {
                "url": elements_data["url"],
                "status_code": elements_data["status_code"],
                "content_type": elements_data["content_type"],
                "title": elements_data["title"],
                "content_length": elements_data["content_length"],
                "content_preview": elements_data.get("content_preview", "")
            },
            "error": "AI 分析失败"
        }
    
    # 线程安全地保存结果
    with results_lock:
        results = load_results()
        results.append(result)
        save_progress(actual_line, results)  # 使用实际行号
    
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
            # 加载已有结果并显示批次信息
            existing_results = load_results(verbose=True)
            if existing_results:
                print(f"[+] 已加载 {len(existing_results)} 个已有结果")
    
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
        results = load_results(verbose=(args.resume or start_line is not None))
        
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
            current_line = domain_info.get("line", (start_line or 1) + i - 1)  # 使用实际行号
            
            print(f"\n[{i}/{len(domains)}] 处理域名: {domain} (排名: {rank}, 行号: {current_line})")
            
            # 检查是否已处理
            already_processed = any(
                r.get("rank") == rank and r.get("domain") == domain
                for r in results
            )
            
            if already_processed:
                print(f"[*] 已处理过，跳过")
                continue
            
            # 获取主页内容并提取元素
            print(f"[*] 获取主页内容并提取元素...")
            elements_data = fetch_and_extract_elements(domain)
            
            if not elements_data:
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
            
            print(f"[+] 成功获取主页内容并提取元素")
            print(f"    URL: {elements_data['url']}")
            print(f"    标题: {elements_data['title']}")
            elements = elements_data.get('elements', {})
            print(f"    提取的元素: {len(elements.get('buttons', []))} 个按钮, {len(elements.get('links', []))} 个链接, {len(elements.get('inputs', []))} 个输入框")
            
            # 两阶段 AI 分析：先用快速模型，如果出错或结果是"可能使用"则用更准确的模型重新判断
            print(f"[*] 第一阶段：使用快速模型 (gemini-2.0-flash-exp) 分析 WebRTC 服务...")
            ai_result = analyze_webrtc_with_ai(domain, elements_data, api_key, "gemini-2.0-flash-exp")
            
            # 如果第一次判断失败（返回 None），使用更准确的模型重新判断
            if not ai_result:
                print(f"[*] 第一阶段分析失败，使用更准确模型 (gemini-2.5-pro) 重新尝试...")
                ai_result = analyze_webrtc_with_ai(domain, elements_data, api_key, "gemini-2.5-pro")
                if ai_result:
                    print(f"[+] 使用昂贵模型分析成功")
                else:
                    print(f"[!] 昂贵模型分析也失败")
            # 如果第一次判断结果是"可能使用"，使用更准确的模型重新判断
            elif ai_result.get("webrtc_usage") == "可能使用":
                print(f"[*] 第一阶段结果为'可能使用'，使用更准确模型 (gemini-2.5-pro) 重新判断...")
                second_result = analyze_webrtc_with_ai(domain, elements_data, api_key, "gemini-2.5-pro")
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
                
                result = {
                    "rank": rank,
                    "domain": domain,
                    "line": current_line,
                    "timestamp": datetime.now().isoformat(),
                    "status": "success",
                    "page_info": {
                        "url": elements_data["url"],
                        "status_code": elements_data["status_code"],
                        "content_type": elements_data["content_type"],
                        "title": elements_data["title"],
                        "content_length": elements_data["content_length"],
                        "content_preview": elements_data.get("content_preview", "")
                    },
                    "ai_analysis": {
                        "webrtc_usage": webrtc_usage,
                        "has_webrtc": has_webrtc,
                        "confidence": confidence,
                        "evidence": evidence,
                        "reasoning": reasoning
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
                        "url": elements_data["url"],
                        "status_code": elements_data["status_code"],
                        "content_type": elements_data["content_type"],
                        "title": elements_data["title"],
                        "content_length": elements_data["content_length"],
                        "content_preview": elements_data.get("content_preview", "")
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
    
    # 显示所有批次文件信息
    print(f"\n结果文件:")
    batch_num = 1
    total_batches = 0
    while True:
        batch_file = get_results_file_path(batch_num)
        if os.path.exists(batch_file):
            try:
                with open(batch_file, 'r', encoding='utf-8') as f:
                    batch_results = json.load(f)
                    print(f"  批次 {batch_num}: {batch_file} ({len(batch_results)} 个结果)")
                    total_batches += 1
            except:
                pass
            batch_num += 1
        else:
            break
    
    if total_batches == 0:
        print(f"  无结果文件")
    else:
        print(f"\n共 {total_batches} 个批次文件")


if __name__ == "__main__":
    # 禁用 SSL 警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()

