#!/usr/bin/env python3
"""
页面元素提取器
从网页中提取 <button>, <a>, <input> 元素的文本和属性
"""

import re
import html
import time
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Optional, Dict, List
from bs4 import BeautifulSoup
import requests


def _resolve_domain(domain: str, timeout: float) -> bool:
    """在给定时间内解析域名"""
    if timeout <= 0:
        return False

    def _worker():
        socket.getaddrinfo(domain, None)
        return True

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_worker)
        try:
            return future.result(timeout=timeout)
        except FuturesTimeoutError:
            print(f"[!] 解析域名 {domain} 超时 ({timeout:.2f}s)")
            return False
        except socket.gaierror as e:
            print(f"[!] 解析域名 {domain} 失败: {e}")
            return False


def _fetch_url(url: str, connect_timeout: float, read_timeout: float, total_timeout: float):
    """在线程中执行 HTTP 请求，确保整体超时受控"""

    if total_timeout <= 0:
        return None

    def _worker():
        return requests.get(
            url,
            headers=REQUEST_HEADERS,
            timeout=(connect_timeout, read_timeout),
            allow_redirects=True,
            verify=False  # 忽略 SSL 证书验证
        )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_worker)
        try:
            return future.result(timeout=total_timeout)
        except FuturesTimeoutError:
            print(f"[!] 请求 {url} 超过总超时 {total_timeout:.2f}s，取消等待")
            return None

# 导入配置文件
from domain_scanner_config import (
    REQUEST_HEADERS,
    DEFAULT_TIMEOUT,
    DEFAULT_MAX_CONTENT_LENGTH
)


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
    print(f"[*] 开始获取 {domain} 的主页内容，总超时 {DEFAULT_TIMEOUT} 秒")
    start_time = time.monotonic()

    for url in urls:
        elapsed = time.monotonic() - start_time
        remaining_time = DEFAULT_TIMEOUT - elapsed
        if remaining_time <= 0:
            print(f"[!] 获取 {domain} 超出总超时 {DEFAULT_TIMEOUT} 秒，停止尝试")
            break
        print(f"[*] 尝试访问 {url} (已耗时 {elapsed:.2f}s，剩余 {remaining_time:.2f}s)")

        dns_timeout = min(3.0, remaining_time)
        if not _resolve_domain(domain, dns_timeout):
            print(f"[!] DNS 解析 {domain} 失败或超时，跳过 {url}")
            continue
        print(f"[*] DNS 解析 {domain} 成功，用时 {time.monotonic() - start_time:.2f}s")

        connect_timeout = min(3.0, remaining_time)
        read_timeout = max(0.5, remaining_time - connect_timeout)

        try:
            response = _fetch_url(url, connect_timeout, read_timeout, remaining_time)
            if response is None:
                continue
            
            # 检查状态码
            if response.status_code == 200:
                print(f"[+] {url} 请求成功，开始处理内容（耗时 {time.monotonic() - start_time:.2f}s）")
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
                content = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', content)
                
                # 限制内容长度
                original_length = len(content)
                if len(content) > DEFAULT_MAX_CONTENT_LENGTH:
                    content = content[:DEFAULT_MAX_CONTENT_LENGTH] + "\n[内容已截断...]"
                
                # 获取响应体前50个字符，用于检查编码问题
                content_preview = content[:50] if content else ""
                
                result = {
                    "url": url,
                    "status_code": response.status_code,
                    "content": content,
                    "content_length": original_length,
                    "content_type": response.headers.get("Content-Type", ""),
                    "title": extract_title(content),
                    "content_preview": content_preview
                }
                response.close()
                return result
            else:
                print(f"[!] {url} 响应状态码 {response.status_code}，继续尝试其他协议")
                response.close()
        except requests.exceptions.SSLError as e:
            # SSL 错误，尝试下一个 URL
            print(f"[!] {url} SSL 错误: {e}，尝试下一种协议")
            continue
        except requests.exceptions.Timeout:
            # 超时，尝试下一个 URL
            print(f"[!] {url} 请求超时（已耗时 {time.monotonic() - start_time:.2f}s），尝试下一种协议")
            continue
        except requests.exceptions.RequestException as e:
            # 其他请求错误，尝试下一个 URL
            print(f"[!] {url} 请求异常: {e}，尝试下一种协议")
            continue
        except Exception as e:
            # 其他异常（可能是编码问题）
            print(f"[!] 处理响应时出错: {e}")
            continue
    
    return None


def extract_title(content: str) -> str:
    """从 HTML 内容中提取标题"""
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


def extract_elements(html_content: str) -> Dict[str, List[Dict]]:
    """
    从 HTML 内容中提取 <button>, <a>, <input> 元素的文本和属性
    
    Args:
        html_content: HTML 内容字符串
        
    Returns:
        包含提取元素的字典，格式为:
        {
            "buttons": [...],
            "links": [...],
            "inputs": [...]
        }
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
    except Exception as e:
        print(f"[!] BeautifulSoup 解析失败: {e}")
        # 如果 BeautifulSoup 失败，使用正则表达式作为后备方案
        return extract_elements_regex(html_content)
    
    elements = {
        "buttons": [],
        "links": [],
        "inputs": []
    }
    
    # 提取 <button> 元素
    buttons = soup.find_all('button')
    for button in buttons:
        button_data = {
            "text": button.get_text(strip=True),
            "attributes": {}
        }
        # 提取所有属性
        for attr_name, attr_value in button.attrs.items():
            if isinstance(attr_value, list):
                button_data["attributes"][attr_name] = ' '.join(attr_value)
            else:
                button_data["attributes"][attr_name] = str(attr_value)
        elements["buttons"].append(button_data)
    
    # 提取 <a> 元素
    links = soup.find_all('a')
    for link in links:
        link_data = {
            "text": link.get_text(strip=True),
            "attributes": {}
        }
        # 提取所有属性
        for attr_name, attr_value in link.attrs.items():
            if isinstance(attr_value, list):
                link_data["attributes"][attr_name] = ' '.join(attr_value)
            else:
                link_data["attributes"][attr_name] = str(attr_value)
        elements["links"].append(link_data)
    
    # 提取 <input> 元素
    inputs = soup.find_all('input')
    for input_elem in inputs:
        input_data = {
            "text": "",  # input 元素通常没有文本内容
            "attributes": {}
        }
        # 提取所有属性
        for attr_name, attr_value in input_elem.attrs.items():
            if isinstance(attr_value, list):
                input_data["attributes"][attr_name] = ' '.join(attr_value)
            else:
                input_data["attributes"][attr_name] = str(attr_value)
        # 对于 input，value 属性通常包含文本
        if 'value' in input_data["attributes"]:
            input_data["text"] = input_data["attributes"]["value"]
        elements["inputs"].append(input_data)
    
    return elements


def extract_elements_regex(html_content: str) -> Dict[str, List[Dict]]:
    """
    使用正则表达式提取元素（BeautifulSoup 失败时的后备方案）
    
    Args:
        html_content: HTML 内容字符串
        
    Returns:
        包含提取元素的字典
    """
    elements = {
        "buttons": [],
        "links": [],
        "inputs": []
    }
    
    # 提取 <button> 元素
    button_pattern = r'<button([^>]*)>(.*?)</button>'
    for match in re.finditer(button_pattern, html_content, re.IGNORECASE | re.DOTALL):
        attrs_str = match.group(1)
        text = match.group(2).strip()
        # 解码 HTML 实体
        try:
            text = html.unescape(text)
        except:
            pass
        
        # 提取属性
        attributes = {}
        attr_pattern = r'(\w+)=["\']([^"\']*)["\']'
        for attr_match in re.finditer(attr_pattern, attrs_str):
            attributes[attr_match.group(1)] = attr_match.group(2)
        
        elements["buttons"].append({
            "text": text,
            "attributes": attributes
        })
    
    # 提取 <a> 元素
    link_pattern = r'<a([^>]*)>(.*?)</a>'
    for match in re.finditer(link_pattern, html_content, re.IGNORECASE | re.DOTALL):
        attrs_str = match.group(1)
        text = match.group(2).strip()
        # 解码 HTML 实体
        try:
            text = html.unescape(text)
        except:
            pass
        
        # 提取属性
        attributes = {}
        attr_pattern = r'(\w+)=["\']([^"\']*)["\']'
        for attr_match in re.finditer(attr_pattern, attrs_str):
            attributes[attr_match.group(1)] = attr_match.group(2)
        
        elements["links"].append({
            "text": text,
            "attributes": attributes
        })
    
    # 提取 <input> 元素（自闭合标签）
    input_pattern = r'<input([^>]*)/?>'
    for match in re.finditer(input_pattern, html_content, re.IGNORECASE):
        attrs_str = match.group(1)
        
        # 提取属性
        attributes = {}
        attr_pattern = r'(\w+)=["\']([^"\']*)["\']'
        for attr_match in re.finditer(attr_pattern, attrs_str):
            attributes[attr_match.group(1)] = attr_match.group(2)
        
        # 对于 input，value 属性通常包含文本
        text = attributes.get('value', '')
        
        elements["inputs"].append({
            "text": text,
            "attributes": attributes
        })
    
    return elements


def fetch_and_extract_elements(domain: str) -> Optional[Dict]:
    """
    获取域名主页并提取 <button>, <a>, <input> 元素
    
    Args:
        domain: 域名
        
    Returns:
        包含页面信息和提取元素的字典，如果失败返回 None
    """
    # 获取主页内容
    page_content = fetch_homepage(domain)
    if not page_content:
        return None
    
    # 提取元素
    elements = extract_elements(page_content["content"])
    
    return {
        "url": page_content["url"],
        "status_code": page_content["status_code"],
        "content_type": page_content["content_type"],
        "title": page_content["title"],
        "content_length": page_content["content_length"],
        "content_preview": page_content.get("content_preview", ""),
        "elements": elements
    }


def format_elements_for_ai(elements_data: Dict) -> str:
    """
    将提取的元素格式化为适合 AI 分析的文本格式
    
    Args:
        elements_data: 包含 elements 的字典（fetch_and_extract_elements 的返回值）
        
    Returns:
        格式化的文本字符串
    """
    if not elements_data or "elements" not in elements_data:
        return ""
    
    elements = elements_data["elements"]
    lines = []
    
    # 页面基本信息
    lines.append(f"页面标题: {elements_data.get('title', 'N/A')}")
    lines.append(f"页面 URL: {elements_data.get('url', 'N/A')}")
    lines.append("")
    
    # 按钮元素
    lines.append("=== 按钮元素 (buttons) ===")
    if elements.get("buttons"):
        for i, button in enumerate(elements["buttons"], 1):
            lines.append(f"\n按钮 {i}:")
            lines.append(f"  文本: {button['text']}")
            if button.get("attributes"):
                lines.append("  属性:")
                for attr_name, attr_value in button["attributes"].items():
                    lines.append(f"    {attr_name}: {attr_value}")
    else:
        lines.append("无")
    lines.append("")
    
    # 链接元素
    lines.append("=== 链接元素 (links) ===")
    if elements.get("links"):
        for i, link in enumerate(elements["links"], 1):
            lines.append(f"\n链接 {i}:")
            lines.append(f"  文本: {link['text']}")
            if link.get("attributes"):
                lines.append("  属性:")
                for attr_name, attr_value in link["attributes"].items():
                    lines.append(f"    {attr_name}: {attr_value}")
    else:
        lines.append("无")
    lines.append("")
    
    # 输入元素
    lines.append("=== 输入元素 (inputs) ===")
    if elements.get("inputs"):
        for i, input_elem in enumerate(elements["inputs"], 1):
            lines.append(f"\n输入 {i}:")
            if input_elem.get("text"):
                lines.append(f"  文本/值: {input_elem['text']}")
            if input_elem.get("attributes"):
                lines.append("  属性:")
                for attr_name, attr_value in input_elem["attributes"].items():
                    lines.append(f"    {attr_name}: {attr_value}")
    else:
        lines.append("无")
    
    return "\n".join(lines)


if __name__ == "__main__":
    # 测试功能
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python3 page_element_extractor.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    print(f"正在提取域名 {domain} 的页面元素...")
    
    result = fetch_and_extract_elements(domain)
    if result:
        print(f"\n页面标题: {result['title']}")
        print(f"页面 URL: {result['url']}")
        print(f"\n提取的元素:")
        print(format_elements_for_ai(result))
    else:
        print("无法获取页面内容")

