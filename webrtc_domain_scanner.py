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

# OpenRouter API 配置
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# 默认配置
DEFAULT_MODEL = "openai/gpt-4o-mini"  # 使用更经济的模型
DEFAULT_TIMEOUT = 10  # HTTP 请求超时时间（秒）
DEFAULT_MAX_CONTENT_LENGTH = 50000  # 最大页面内容长度（字符）
DEFAULT_DELAY = 1  # 请求之间的延迟（秒）

# 结果文件
RESULTS_FILE = "webrtc_scan_results.json"
PROGRESS_FILE = "webrtc_scan_progress.json"

# 全局变量用于优雅退出
interrupted = False


def signal_handler(sig, frame):
    """处理 Ctrl+C 信号，优雅退出"""
    global interrupted
    print("\n[!] 接收到中断信号，正在保存进度...")
    interrupted = True


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
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    
    for url in urls:
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True,
                verify=False  # 忽略 SSL 证书验证
            )
            
            # 检查状态码
            if response.status_code == 200:
                content = response.text
                
                # 限制内容长度
                if len(content) > DEFAULT_MAX_CONTENT_LENGTH:
                    content = content[:DEFAULT_MAX_CONTENT_LENGTH] + "\n[内容已截断...]"
                
                return {
                    "url": url,
                    "status_code": response.status_code,
                    "content": content,
                    "content_length": len(response.text),
                    "content_type": response.headers.get("Content-Type", ""),
                    "title": extract_title(content)
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
    
    return None


def extract_title(content: str) -> str:
    """从 HTML 内容中提取标题"""
    import re
    # 尝试提取 <title> 标签
    title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
    if title_match:
        return title_match.group(1).strip()
    
    # 尝试提取 <h1> 标签
    h1_match = re.search(r'<h1[^>]*>([^<]+)</h1>', content, re.IGNORECASE)
    if h1_match:
        return h1_match.group(1).strip()
    
    return ""


def analyze_webrtc_with_ai(domain: str, page_content: Dict) -> Optional[Dict]:
    """
    使用 AI 模型分析页面内容，判断是否包含 WebRTC 相关服务
    
    Args:
        domain: 域名
        page_content: 页面内容字典
        
    Returns:
        AI 分析结果，包含判断和原因
    """
    if not OPENROUTER_API_KEY:
        print("[!] 错误: 未设置 OPENROUTER_API_KEY 环境变量")
        return None
    
    # 构建提示词
    prompt = f"""请分析以下网站内容，判断该域名是否可能提供 WebRTC 相关的服务。

域名: {domain}
URL: {page_content['url']}
状态码: {page_content['status_code']}
内容类型: {page_content['content_type']}
标题: {page_content['title']}

页面内容:
{page_content['content']}

请从以下角度分析:
1. 页面文本中是否提到 WebRTC、STUN、TURN、ICE、RTCPeerConnection 等相关技术
2. 页面是否涉及视频会议、实时通信、语音通话、屏幕共享等功能
3. 是否有相关的 JavaScript 库引用（如 SimpleWebRTC、PeerJS、Socket.io 等）
4. 页面的业务类型是否可能使用 WebRTC 技术

请以 JSON 格式返回结果:
{{
    "has_webrtc": true/false,
    "confidence": "high/medium/low",
    "reasons": ["原因1", "原因2", ...],
    "keywords_found": ["关键词1", "关键词2", ...]
}}"""

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/turn-client",
        "X-Title": "WebRTC Domain Scanner"
    }
    
    payload = {
        "model": DEFAULT_MODEL,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "stream": True,
        "temperature": 0.3
    }
    
    try:
        response = requests.post(
            OPENROUTER_API_URL,
            headers=headers,
            json=payload,
            stream=True,
            timeout=60
        )
        
        # 检查初始状态码
        if response.status_code != 200:
            error_data = response.json()
            print(f"[!] API 错误: {error_data.get('error', {}).get('message', 'Unknown error')}")
            return None
        
        # 处理流式响应
        buffer = ""
        full_content = ""
        
        for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
            if interrupted:
                break
                
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
                            print(f"[!] 流式响应错误: {data_obj['error'].get('message', 'Unknown error')}")
                            return None
                        
                        # 提取内容
                        delta = data_obj.get('choices', [{}])[0].get('delta', {})
                        content = delta.get('content', '')
                        if content:
                            full_content += content
                            print(content, end='', flush=True)
                            
                        # 检查 finish_reason
                        finish_reason = data_obj.get('choices', [{}])[0].get('finish_reason')
                        if finish_reason == 'error':
                            print("\n[!] 流式响应因错误终止")
                            return None
                            
                    except json.JSONDecodeError:
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
                    "has_webrtc": None,
                    "confidence": "unknown",
                    "reasons": ["无法解析 AI 响应"],
                    "raw_response": full_content
                }
        except json.JSONDecodeError:
            return {
                "has_webrtc": None,
                "confidence": "unknown",
                "reasons": ["AI 响应格式错误"],
                "raw_response": full_content
            }
            
    except requests.exceptions.RequestException as e:
        print(f"[!] API 请求失败: {e}")
        return None


def save_progress(current_line: int, results: List[Dict]):
    """保存进度和结果"""
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
    """加载上次的进度"""
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
            progress = json.load(f)
            return progress.get("last_line", 1)
    return 1


def main():
    parser = argparse.ArgumentParser(
        description="扫描域名列表，使用 AI 判断是否包含 WebRTC 相关服务"
    )
    parser.add_argument(
        "--csv",
        default="tranco_top_1m_domains/top-1m.csv",
        help="CSV 文件路径（默认: tranco_top_1m_domains/top-1m.csv）"
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
    
    args = parser.parse_args()
    
    # 设置模型
    global DEFAULT_MODEL
    if args.model:
        DEFAULT_MODEL = args.model
    
    # 检查 API Key
    if not OPENROUTER_API_KEY:
        print("[!] 错误: 请设置 OPENROUTER_API_KEY 环境变量")
        print("    export OPENROUTER_API_KEY='your-api-key'")
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
    
    # 加载已有结果
    results = []
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
            results = json.load(f)
    
    # 处理每个域名
    for i, domain_info in enumerate(domains, start=1):
        if interrupted:
            print("\n[!] 已中断，保存进度...")
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
        
        # 使用 AI 分析
        print(f"[*] 使用 AI 分析 WebRTC 服务...")
        ai_result = analyze_webrtc_with_ai(domain, page_content)
        
        if ai_result:
            has_webrtc = ai_result.get("has_webrtc", None)
            confidence = ai_result.get("confidence", "unknown")
            reasons = ai_result.get("reasons", [])
            keywords = ai_result.get("keywords_found", [])
            
            print(f"[+] AI 分析结果:")
            print(f"    包含 WebRTC: {has_webrtc}")
            print(f"    置信度: {confidence}")
            if reasons:
                print(f"    原因: {', '.join(reasons[:3])}")
            
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
                    "content_length": page_content["content_length"]
                },
                "ai_analysis": {
                    "has_webrtc": has_webrtc,
                    "confidence": confidence,
                    "reasons": reasons,
                    "keywords_found": keywords
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
                    "content_length": page_content["content_length"]
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
    
    print(f"总计: {total}")
    print(f"成功: {success}")
    print(f"失败: {failed}")
    print(f"AI 分析失败: {ai_failed}")
    print(f"包含 WebRTC: {has_webrtc}")
    print(f"\n结果已保存到: {RESULTS_FILE}")


if __name__ == "__main__":
    # 禁用 SSL 警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()

