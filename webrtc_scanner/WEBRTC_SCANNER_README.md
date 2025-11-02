# WebRTC 域名扫描器

从 Tranco Top 1M 域名列表中读取域名，访问主页内容，使用 AI 模型判断是否包含 WebRTC 相关服务。

## 功能特点

- 从 CSV 文件读取域名列表（Tranco Top 1M）
- 自动尝试 HTTP/HTTPS 访问域名主页
- 提取页面标题和内容
- 使用 OpenRouter API 调用 AI 模型进行流式分析
- 智能判断是否包含 WebRTC 相关服务
- 支持断点续传（从上次停止位置继续）
- 自动保存进度和结果

## 依赖

```bash
pip install requests urllib3
```

## 配置

配置文件: `domain_scanner_config.py`

### 方式1: 使用环境变量（推荐）

```bash
export OPENROUTER_API_KEY='your-api-key-here'
```

### 方式2: 直接修改配置文件

编辑 `domain_scanner_config.py`，设置 `OPENROUTER_API_KEY` 变量：

```python
OPENROUTER_API_KEY = "your-api-key-here"
```

## 使用方法

### 基本用法

```bash
# 从第 1 行开始处理 10 个域名
python3 webrtc_domain_scanner.py --csv tranco_top_1m_domains/top-1m.csv --max 10

# 从第 100 行开始处理 50 个域名
python3 webrtc_domain_scanner.py --csv tranco_top_1m_domains/top-1m.csv --start 100 --max 50

# 使用指定的 AI 模型
python3 webrtc_domain_scanner.py --csv tranco_top_1m_domains/top-1m.csv --model "openai/gpt-4o" --max 10

# 从上次停止的位置继续
python3 webrtc_domain_scanner.py --csv tranco_top_1m_domains/top-1m.csv --resume
```

### 参数说明

- `--csv`: CSV 文件路径（默认: `tranco_top_1m_domains/top-1m.csv`）
- `--start`: 从第几行开始（1-based）
- `--max`: 最多处理多少个域名
- `--model`: OpenRouter 模型名称（默认: `openai/gpt-4o-mini`）
- `--delay`: 请求之间的延迟（秒，默认: 1）
- `--resume`: 从上次停止的位置继续

## 输出文件

- `webrtc_scan_results.json`: 完整扫描结果
- `webrtc_scan_progress.json`: 扫描进度（用于断点续传）

## 结果格式

```json
{
  "rank": "1",
  "domain": "google.com",
  "line": 1,
  "timestamp": "2025-10-29T08:00:00",
  "status": "success",
  "page_info": {
    "url": "https://google.com",
    "status_code": 200,
    "content_type": "text/html",
    "title": "Google",
    "content_length": 50000
  },
  "ai_analysis": {
    "has_webrtc": true,
    "confidence": "high",
    "reasons": ["页面包含 WebRTC 相关关键词", "业务类型涉及实时通信"],
    "keywords_found": ["WebRTC", "RTCPeerConnection", "video conference"]
  }
}
```

## 注意事项

1. **API Key**: 需要有效的 OpenRouter API Key，并且账户需要有足够的余额
2. **速率限制**: OpenRouter 有速率限制，建议适当设置 `--delay` 参数
3. **超时**: HTTP 请求默认超时 10 秒，可通过修改代码调整
4. **内容长度**: 页面内容限制为 50,000 字符，可通过修改 `DEFAULT_MAX_CONTENT_LENGTH` 调整
5. **SSL 验证**: 默认忽略 SSL 证书验证（用于测试环境）

## 示例输出

```
[+] 读取域名列表: tranco_top_1m_domains/top-1m.csv
[+] 找到 10 个域名待处理

[1/10] 处理域名: google.com (排名: 1, 行号: 1)
[*] 获取主页内容...
[+] 成功获取主页内容 (50000 字符)
    URL: https://google.com
    标题: Google
[*] 使用 AI 分析 WebRTC 服务...
[+] AI 分析结果:
    包含 WebRTC: true
    置信度: high
    原因: 页面包含 WebRTC 相关关键词, 业务类型涉及实时通信

======================================================================
📊 扫描完成统计
======================================================================
总计: 10
成功: 10
失败: 0
AI 分析失败: 0
包含 WebRTC: 3

结果已保存到: webrtc_scan_results.json
```

## 支持的模型

可以使用任何 OpenRouter 支持的模型，推荐：

- `openai/gpt-4o-mini`: 经济实惠，速度快
- `openai/gpt-4o`: 性能更好，准确性高
- `anthropic/claude-3-haiku`: 速度快，成本低
- `google/gemini-pro`: Google 模型

查看所有可用模型: https://openrouter.ai/models

