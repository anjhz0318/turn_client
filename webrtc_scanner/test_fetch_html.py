#!/usr/bin/env python3
"""
测试脚本：访问指定 URL 并输出 HTML 内容
用于测试 HTTP 请求和编码处理
"""

import sys
import argparse
import requests
import urllib3

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_html(url: str, timeout: int = 10) -> str:
    """
    获取 URL 的 HTML 内容
    
    Args:
        url: 要访问的 URL
        timeout: 超时时间（秒）
        
    Returns:
        HTML 内容字符串
    """
    headers = {
        # User-Agent: 模拟 Chrome 浏览器
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        
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
        
        # Referer: 来源页面（可选，某些情况下有助于绕过反爬虫）
        # 'Referer': 'https://www.google.com/',
    }
    
    try:
        print(f"[+] 正在访问: {url}")
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            verify=False  # 忽略 SSL 证书验证
        )
        
        print(f"[+] HTTP 状态码: {response.status_code}")
        print(f"[+] Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"[+] Content-Length: {len(response.content)} bytes")
        print()
        
        # 正确处理编码
        if response.status_code == 200:
            # 尝试检测和设置编码
            if response.encoding is None or response.encoding == 'ISO-8859-1':
                # 尝试从 Content-Type 头获取编码
                content_type = response.headers.get("Content-Type", "")
                if 'charset=' in content_type:
                    try:
                        charset = content_type.split('charset=')[1].split(';')[0].strip().strip('"\'')
                        response.encoding = charset
                        print(f"[+] 从 Content-Type 检测到编码: {charset}")
                    except:
                        pass
                
                # 如果还是无法确定，尝试检测编码
                if response.encoding is None or response.encoding == 'ISO-8859-1':
                    try:
                        import chardet
                        detected = chardet.detect(response.content)
                        if detected and detected.get('encoding'):
                            response.encoding = detected['encoding']
                            print(f"[+] 使用 chardet 检测到编码: {detected['encoding']} (置信度: {detected.get('confidence', 0):.2f})")
                        else:
                            response.encoding = 'utf-8'
                            print(f"[+] 默认使用编码: UTF-8")
                    except ImportError:
                        response.encoding = 'utf-8'
                        print(f"[+] chardet 未安装，默认使用编码: UTF-8")
                    except Exception as e:
                        response.encoding = 'utf-8'
                        print(f"[!] 编码检测失败，默认使用 UTF-8: {e}")
            
            # 获取文本内容，确保是 UTF-8
            try:
                content = response.text
                # 如果文本包含无法解码的字符，尝试重新编码
                if not isinstance(content, str):
                    content = str(content, encoding='utf-8', errors='replace')
            except UnicodeDecodeError:
                # 如果解码失败，尝试使用 errors='replace'
                content = response.content.decode('utf-8', errors='replace')
                print(f"[!] UTF-8 解码失败，使用 replace 模式")
            except Exception:
                # 最后尝试：先解码为字节，再尝试常见编码
                try:
                    content = response.content.decode('utf-8', errors='replace')
                except:
                    content = response.content.decode('latin-1', errors='replace')
                    print(f"[!] 使用 latin-1 作为后备编码")
            
            # 清理内容：移除控制字符，但保留换行符和制表符
            import re
            # 只移除真正的控制字符（\x00-\x08, \x0b-\x0c, \x0e-\x1f, \x7f-\x9f）
            # 保留 \x09 (tab), \x0a (LF), \x0d (CR)
            content = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', content)
            
            return content
        else:
            print(f"[!] HTTP 错误: {response.status_code}")
            return response.text if hasattr(response, 'text') else str(response.content, errors='replace')
            
    except requests.exceptions.Timeout:
        print(f"[!] 请求超时（超过 {timeout} 秒）")
        return None
    except requests.exceptions.SSLError as e:
        print(f"[!] SSL 错误: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求错误: {e}")
        return None
    except Exception as e:
        print(f"[!] 未知错误: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="访问指定 URL 并输出 HTML 内容"
    )
    parser.add_argument(
        "--url",
        default="https://www.webex.com/",
        help="要访问的 URL（默认: https://www.webex.com/）"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="超时时间（秒，默认: 10）"
    )
    parser.add_argument(
        "--output",
        help="输出到文件（可选）"
    )
    parser.add_argument(
        "--max-length",
        type=int,
        help="最大输出长度（字符数，可选）"
    )
    
    args = parser.parse_args()
    
    # 获取 HTML 内容
    html_content = fetch_html(args.url, args.timeout)
    
    if html_content is None:
        print("[!] 无法获取 HTML 内容")
        sys.exit(1)
    
    # 限制输出长度
    if args.max_length and len(html_content) > args.max_length:
        print(f"\n[!] 内容过长（{len(html_content)} 字符），截断到 {args.max_length} 字符")
        html_content = html_content[:args.max_length] + "\n... [已截断]"
    
    # 输出内容
    if args.output:
        # 保存到文件
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"\n[+] HTML 内容已保存到: {args.output}")
            print(f"[+] 文件大小: {len(html_content)} 字符")
        except Exception as e:
            print(f"[!] 保存文件失败: {e}")
            sys.exit(1)
    else:
        # 输出到标准输出
        print("\n" + "="*60)
        print("HTML 内容:")
        print("="*60)
        print(html_content)
        print("="*60)
        print(f"\n总长度: {len(html_content)} 字符")


if __name__ == "__main__":
    main()

