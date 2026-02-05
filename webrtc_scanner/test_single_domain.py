#!/usr/bin/env python3
"""
单个域名测试脚本
用于测试主扫描脚本的核心功能，只测试单个指定网站
"""

import sys
import json
import argparse
from datetime import datetime
import urllib3

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 导入主脚本的核心函数
from webrtc_domain_scanner import (
    analyze_webrtc_with_ai,
    get_api_key,
    DEFAULT_MODEL,
    validate_config
)

# 导入页面元素提取器
from page_element_extractor import (
    fetch_and_extract_elements,
    format_elements_for_ai
)


def test_single_domain(domain: str, api_key: str, model: str):
    """
    测试单个域名的 WebRTC 扫描功能
    
    Args:
        domain: 要测试的域名
        api_key: OpenRouter API Key
        model: AI 模型名称
    """
    print("="*60)
    print(f"测试域名: {domain}")
    print("="*60)
    
    # 获取主页内容并提取元素
    print(f"\n[1/3] 获取主页内容并提取元素...")
    elements_data = fetch_and_extract_elements(domain)
    
    if not elements_data:
        print(f"[!] 无法获取主页内容")
        return None
    
    print(f"[+] 成功获取主页内容并提取元素")
    print(f"    URL: {elements_data['url']}")
    print(f"    状态码: {elements_data['status_code']}")
    print(f"    Content-Type: {elements_data['content_type']}")
    print(f"    标题: {elements_data['title']}")
    print(f"    内容长度: {elements_data['content_length']} 字符")
    elements = elements_data.get('elements', {})
    print(f"    提取的元素: {len(elements.get('buttons', []))} 个按钮, {len(elements.get('links', []))} 个链接, {len(elements.get('inputs', []))} 个输入框")
    
    # 计算并输出元素信息文本长度
    from page_element_extractor import format_elements_for_ai
    elements_text = format_elements_for_ai(elements_data)
    elements_text_length = len(elements_text)
    print(f"    元素信息文本长度: {elements_text_length} 字符（用于估算 token 消耗）")
    
    # 两阶段 AI 分析：先用快速模型，如果出错或结果是"Possible Use"则用更准确的模型重新判断
    print(f"\n[2/3] 第一阶段：使用快速模型 (gemini-2.0-flash-exp) 分析 WebRTC 服务...")
    ai_result = analyze_webrtc_with_ai(domain, elements_data, api_key, "gemini-2.0-flash-exp")
    
    # 如果第一次判断失败（返回 None），使用更准确的模型重新判断
    if not ai_result:
        print(f"[!] 第一阶段分析失败，使用更准确模型 (gemini-2.5-pro) 重新尝试...")
        ai_result = analyze_webrtc_with_ai(domain, elements_data, api_key, "gemini-2.5-pro")
        if ai_result:
            print(f"[+] 使用昂贵模型分析成功")
        else:
            print(f"[!] 昂贵模型分析也失败")
            return {
                "domain": domain,
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
                "error": "AI 分析失败（廉价模型和昂贵模型都失败）"
            }
    
    # 解析第一阶段的 JSON 格式
    webrtc_usage = ai_result.get("webrtc_usage", "No Evidence of Use")
    evidence = ai_result.get("evidence", [])
    reasoning = ai_result.get("reasoning", "")
    
    print(f"[+] 第一阶段 AI 分析结果:")
    print(f"    WebRTC 使用情况: {webrtc_usage}")
    if evidence:
        print(f"    证据:")
        for ev in evidence[:5]:  # 只显示前5个证据
            print(f"      - {ev}")
    if reasoning:
        print(f"    推理过程: {reasoning[:200]}...")  # 限制长度
    
    # 如果第一次判断结果是"Possible Use"，使用更准确的模型重新判断
    if webrtc_usage == "Possible Use":
        print(f"\n[3/3] 第一阶段结果为'Possible Use'，使用更准确模型 (gemini-2.5-pro) 重新判断...")
        second_result = analyze_webrtc_with_ai(domain, elements_data, api_key, "gemini-2.5-pro")
        if second_result:
            # 以第二次判断的结果为准
            ai_result = second_result
            webrtc_usage = ai_result.get("webrtc_usage", "No Evidence of Use")
            evidence = ai_result.get("evidence", [])
            reasoning = ai_result.get("reasoning", "")
            print(f"[+] 第二阶段判断完成，以本次结果为准")
            print(f"    第二阶段 WebRTC 使用情况: {webrtc_usage}")
            if evidence:
                print(f"    证据:")
                for ev in evidence[:5]:
                    print(f"      - {ev}")
            if reasoning:
                print(f"    推理过程: {reasoning[:200]}...")
        else:
            print(f"[!] 第二阶段判断失败，使用第一阶段结果")
    
    # 将 webrtc_usage 转换为布尔值（用于判断是否需要进行发起通信能力分析）
    has_webrtc = webrtc_usage in ["Confirmed Use", "Possible Use"]
    
    # 根据 webrtc_usage 确定置信度
    if webrtc_usage == "Confirmed Use":
        confidence = "high"
    elif webrtc_usage == "Possible Use":
        confidence = "medium"
    else:
        confidence = "low"
    
    # 构建结果
    result = {
        "domain": domain,
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
            "webrtc_usage": webrtc_usage,  # 新格式：Confirmed Use | Possible Use | No Evidence of Use
            "has_webrtc": has_webrtc,  # 向后兼容：布尔值
            "confidence": confidence,  # 根据 webrtc_usage 推断的置信度
            "evidence": evidence,  # 新格式：证据列表
            "reasoning": reasoning  # 新格式：推理过程
        }
    }
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="测试单个域名的 WebRTC 扫描功能"
    )
    parser.add_argument(
        "domain",
        help="要测试的域名（例如: discord.com）"
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"OpenRouter 模型名称（默认: {DEFAULT_MODEL}）"
    )
    parser.add_argument(
        "--output",
        help="输出结果到 JSON 文件（可选）"
    )
    
    args = parser.parse_args()
    
    # 验证配置
    is_valid, error = validate_config()
    if not is_valid:
        print(f"[!] 配置错误: {error}")
        sys.exit(1)
    
    # 获取 API Key
    api_key = get_api_key()
    if not api_key:
        print("[!] 错误: 请设置 OPENROUTER_API_KEY 环境变量或修改配置文件")
        print("    方式1: export OPENROUTER_API_KEY='your-api-key'")
        print("    方式2: 编辑 domain_scanner_config.py 文件")
        sys.exit(1)
    
    print(f"[+] 使用模型: {args.model}")
    print(f"[+] API Key: {'已设置' if api_key else '未设置'}")
    
    # 测试域名
    result = test_single_domain(args.domain, api_key, args.model)
    
    if result:
        # 输出结果
        print("\n" + "="*60)
        print("📊 测试完成")
        print("="*60)
        
        # 格式化输出 JSON
        result_json = json.dumps(result, indent=2, ensure_ascii=False)
        
        if args.output:
            # 保存到文件
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(result_json)
            print(f"\n结果已保存到: {args.output}")
        else:
            # 输出到控制台
            print("\n完整结果（JSON）:")
            print(result_json)
    else:
        print("\n[!] 测试失败")
        sys.exit(1)


if __name__ == "__main__":
    main()

