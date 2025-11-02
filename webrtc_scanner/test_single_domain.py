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
    fetch_homepage,
    analyze_webrtc_with_ai,
    analyze_webrtc_initiation,
    get_api_key,
    DEFAULT_MODEL,
    validate_config
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
    
    # 获取主页内容
    print(f"\n[1/3] 获取主页内容...")
    page_content = fetch_homepage(domain)
    
    if not page_content:
        print(f"[!] 无法获取主页内容")
        return None
    
    print(f"[+] 成功获取主页内容")
    print(f"    URL: {page_content['url']}")
    print(f"    状态码: {page_content['status_code']}")
    print(f"    Content-Type: {page_content['content_type']}")
    print(f"    标题: {page_content['title']}")
    print(f"    内容长度: {page_content['content_length']} 字符")
    print(f"    内容预览: {repr(page_content.get('content_preview', ''))}")
    
    # 两阶段 AI 分析：先用快速模型，如果结果是"可能使用"则用更准确的模型重新判断
    print(f"\n[2/4] 第一阶段：使用快速模型 (google/gemini-2.0-flash-001) 分析 WebRTC 服务...")
    ai_result = analyze_webrtc_with_ai(domain, page_content, api_key, "google/gemini-2.0-flash-001")
    
    if not ai_result:
        print(f"[!] 第一阶段 AI 分析失败")
        return {
            "domain": domain,
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
            "error": "第一阶段 AI 分析失败"
        }
    
    # 解析第一阶段的 JSON 格式
    webrtc_usage = ai_result.get("webrtc_usage", "未发现使用")
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
    
    # 如果第一次判断结果是"可能使用"，使用更准确的模型重新判断
    if webrtc_usage == "可能使用":
        print(f"\n[3/4] 第一阶段结果为'可能使用'，使用更准确模型 (google/gemini-2.5-pro) 重新判断...")
        second_result = analyze_webrtc_with_ai(domain, page_content, api_key, "google/gemini-2.5-pro")
        if second_result:
            # 以第二次判断的结果为准
            ai_result = second_result
            webrtc_usage = ai_result.get("webrtc_usage", "未发现使用")
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
    has_webrtc = webrtc_usage in ["确定使用", "可能使用"]
    
    # 根据 webrtc_usage 确定置信度
    if webrtc_usage == "确定使用":
        confidence = "high"
    elif webrtc_usage == "可能使用":
        confidence = "medium"
    else:
        confidence = "low"
    
    # 如果判断存在 WebRTC，进行发起通信能力分析
    initiation_analysis = None
    if has_webrtc:
        print(f"\n[4/4] 检测到 WebRTC 服务，分析是否可从网站发起通信...")
        # 使用更准确的模型进行发起通信能力分析
        initiation_analysis = analyze_webrtc_initiation(domain, page_content, api_key, "google/gemini-2.5-pro")
        
        if initiation_analysis:
            can_initiate = initiation_analysis.get("can_initiate", "unknown")
            init_confidence = initiation_analysis.get("confidence", "unknown")
            init_reasons = initiation_analysis.get("reasons", [])
            buttons_found = initiation_analysis.get("buttons_or_components_found", [])
            requires_steps = initiation_analysis.get("requires_additional_steps", False)
            additional_steps = initiation_analysis.get("additional_steps", [])
            
            print(f"[+] 发起通信能力分析结果:")
            print(f"    可以发起: {can_initiate}")
            print(f"    置信度: {init_confidence}")
            if init_reasons:
                print(f"    原因:")
                for reason in init_reasons:
                    print(f"      - {reason}")
            if buttons_found:
                print(f"    发现的按钮/组件:")
                for button in buttons_found:
                    print(f"      - {button}")
            if requires_steps:
                print(f"    需要额外步骤: 是")
                if additional_steps:
                    print(f"    额外步骤:")
                    for step in additional_steps:
                        print(f"      - {step}")
        else:
            print(f"[!] 发起通信能力分析失败")
    else:
        print(f"\n[4/4] 未检测到 WebRTC 服务，跳过发起通信能力分析")
    
    # 构建结果
    result = {
        "domain": domain,
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
            "webrtc_usage": webrtc_usage,  # 新格式：确定使用 | 可能使用 | 未发现使用
            "has_webrtc": has_webrtc,  # 向后兼容：布尔值
            "confidence": confidence,  # 根据 webrtc_usage 推断的置信度
            "evidence": evidence,  # 新格式：证据列表
            "reasoning": reasoning,  # 新格式：推理过程
            "initiation_analysis": initiation_analysis  # 发起通信能力分析
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

