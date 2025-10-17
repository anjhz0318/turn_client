# 修改后的 TURN 客户端使用示例

## turn_client.py 使用示例

### 基本用法
```bash
# UDP TURN 模式（默认）
python3 turn_client.py --target-ip 103.129.252.45 --target-port 25

# 使用自定义TURN服务器
python3 turn_client.py --target-ip 103.129.252.45 --target-port 25 \
  --turn-server turn.example.com --turn-port 3478

# TCP TURN 模式
python3 turn_client.py tcp --target-ip 103.129.252.45 --target-port 25

# 完整 TCP TURN 模式（包含数据连接）
python3 turn_client.py tcp-full --target-ip 103.129.252.45 --target-port 25 \
  --turn-server turn.example.com --turn-port 3478
```

### 参数说明
- `--target-ip`: 目标服务器的IP地址（必需）
- `--target-port`: 目标服务器的端口号（必需）
- `--turn-server`: TURN服务器地址（域名或IP，可选）
- `--turn-port`: TURN服务器端口（可选）
- 模式选择：
  - `udp`: UDP TURN 模式（默认）
  - `tcp`: 基本 TCP TURN 模式
  - `tcp-full`: 完整 TCP TURN 模式（包含数据连接）

## smtp_turn_client.py 使用示例

### 发送邮件
```bash
python3 smtp_turn_client.py \
  --smtp-server 103.129.252.59 \
  --smtp-port 25 \
  --from-addr test@anjhz3.com \
  --to-addr anjhz0318@163.com \
  --subject "测试邮件" \
  --body "这是一封通过TCP TURN发送的测试邮件"

# 使用自定义TURN服务器
python3 smtp_turn_client.py \
  --smtp-server 103.129.252.59 \
  --smtp-port 25 \
  --turn-server turn.example.com \
  --turn-port 3478 \
  --from-addr test@anjhz3.com \
  --to-addr anjhz0318@163.com \
  --subject "测试邮件" \
  --body "这是一封通过TCP TURN发送的测试邮件"
```

### 简单测试
```bash
python3 smtp_turn_client.py test \
  --smtp-server 103.129.252.59 \
  --smtp-port 25

# 使用自定义TURN服务器测试
python3 smtp_turn_client.py test \
  --smtp-server 103.129.252.59 \
  --smtp-port 25 \
  --turn-server turn.example.com \
  --turn-port 3478
```

### 参数说明
- `--smtp-server`: SMTP服务器IP地址（必需）
- `--smtp-port`: SMTP服务器端口（默认：25）
- `--turn-server`: TURN服务器地址（域名或IP，可选）
- `--turn-port`: TURN服务器端口（可选）
- `--from-addr`: 发件人邮箱地址（必需）
- `--to-addr`: 收件人邮箱地址（必需）
- `--subject`: 邮件主题（必需）
- `--body`: 邮件正文（必需）

## dns_turn_client.py 使用示例

### 单个DNS查询
```bash
# 查询A记录
python3 dns_turn_client.py \
  --dns-server 8.8.8.8 \
  --dns-port 53 \
  --domain www.google.com \
  --query-type 1

# 使用自定义TURN服务器查询
python3 dns_turn_client.py \
  --dns-server 8.8.8.8 \
  --dns-port 53 \
  --turn-server turn.example.com \
  --turn-port 3478 \
  --domain www.google.com \
  --query-type 1

# 查询AAAA记录（IPv6）
python3 dns_turn_client.py \
  --dns-server 8.8.8.8 \
  --dns-port 53 \
  --domain www.google.com \
  --query-type 28

# 查询MX记录
python3 dns_turn_client.py \
  --dns-server 8.8.8.8 \
  --dns-port 53 \
  --domain google.com \
  --query-type 15

# 查询NS记录
python3 dns_turn_client.py \
  --dns-server 8.8.8.8 \
  --dns-port 53 \
  --domain google.com \
  --query-type 2
```

### 多个DNS查询测试
```bash
python3 dns_turn_client.py test \
  --dns-server 8.8.8.8 \
  --dns-port 53

# 使用自定义TURN服务器测试
python3 dns_turn_client.py test \
  --dns-server 8.8.8.8 \
  --dns-port 53 \
  --turn-server turn.example.com \
  --turn-port 3478
```

### 参数说明
- `--dns-server`: DNS服务器IP地址（必需）
- `--dns-port`: DNS服务器端口（默认：53）
- `--turn-server`: TURN服务器地址（域名或IP，可选）
- `--turn-port`: TURN服务器端口（可选）
- `--domain`: 要查询的域名（必需）
- `--query-type`: 查询类型（默认：1）
  - 1: A记录（IPv4地址）
  - 28: AAAA记录（IPv6地址）
  - 15: MX记录（邮件交换）
  - 2: NS记录（名称服务器）

## http_turn_client.py 使用示例

### 基本HTTP请求
```bash
# GET请求
python3 http_turn_client.py \
  --target-host www.example.com \
  --target-port 80 \
  --method GET \
  --path /

# POST请求
python3 http_turn_client.py \
  --target-host www.example.com \
  --target-port 80 \
  --method POST \
  --path /api/data \
  --data "key=value" \
  --header "Content-Type: application/x-www-form-urlencoded"
```

### HTTPS请求
```bash
# HTTPS GET请求
python3 http_turn_client.py \
  --target-host www.google.com \
  --https \
  --method GET \
  --path /

# 使用自定义TURN服务器的HTTPS请求
python3 http_turn_client.py \
  --target-host www.google.com \
  --https \
  --turn-server turn.example.com \
  --turn-port 3478 \
  --method GET \
  --path /
```

### 保存响应到文件
```bash
python3 http_turn_client.py \
  --target-host www.example.com \
  --target-port 80 \
  --method GET \
  --path /robots.txt \
  --output robots.txt
```

### 多个请求测试
```bash
python3 http_turn_client.py test \
  --target-host www.example.com \
  --target-port 80
```

### 参数说明
- `--target-host`: 目标HTTP服务器主机名或IP（必需）
- `--target-port`: 目标HTTP服务器端口（可选，HTTP默认80，HTTPS默认443）
- `--turn-server`: TURN服务器地址（域名或IP，可选）
- `--turn-port`: TURN服务器端口（可选）
- `--method`: HTTP方法（默认：GET）
- `--path`: 请求路径（默认：/）
- `--header`: HTTP头部（格式：Key: Value，可多次使用）
- `--data`: 请求体数据（可选）
- `--https`: 使用HTTPS（SSL/TLS）
- `--output`: 将响应保存到文件（可选）

## http3_turn_client.py 使用示例

### 基本HTTP/3请求
```bash
# HTTP/3 GET请求
python3 http3_turn_client.py \
  --target-host www.example.com \
  --target-port 443 \
  --method GET \
  --path /

# 使用自定义TURN服务器
python3 http3_turn_client.py \
  --target-host www.example.com \
  --target-port 443 \
  --turn-server turn.example.com \
  --turn-port 3478 \
  --method GET \
  --path /
```

### 保存响应到文件
```bash
python3 http3_turn_client.py \
  --target-host www.example.com \
  --target-port 443 \
  --method GET \
  --path /robots.txt \
  --output robots.txt
```

### 连接测试
```bash
python3 http3_turn_client.py test \
  --target-host www.example.com \
  --target-port 443
```

### 参数说明
- `--target-host`: 目标HTTP/3服务器主机名或IP（必需）
- `--target-port`: 目标HTTP/3服务器端口（默认：443）
- `--turn-server`: TURN服务器地址（域名或IP，可选）
- `--turn-port`: TURN服务器端口（可选）
- `--method`: HTTP方法（默认：GET）
- `--path`: 请求路径（默认：/）
- `--header`: HTTP头部（格式：Key: Value，可多次使用）
- `--output`: 将响应保存到文件（可选）

## 主要修改内容

1. **turn_client.py**:
   - `main()`, `main_tcp()`, `demo_tcp_with_data_connection()` 函数现在接受 `target_ip` 和 `target_port` 参数
   - 添加了命令行参数解析，支持 `--target-ip` 和 `--target-port` 参数
   - 添加了 `--turn-server` 和 `--turn-port` 参数支持自定义TURN服务器
   - 添加了 `resolve_server_address()` 函数支持域名解析
   - 移除了硬编码的目标IP和端口

2. **smtp_turn_client.py**:
   - `main()` 函数添加了完整的命令行参数支持
   - `test_simple_smtp()` 函数也支持命令行参数
   - 添加了 `--turn-server` 和 `--turn-port` 参数支持自定义TURN服务器
   - 移除了硬编码的SMTP服务器配置
   - 现在可以通过命令行指定所有邮件参数

3. **dns_turn_client.py** (新增):
   - 通过UDP TURN转发DNS查询请求
   - 支持多种DNS记录类型查询（A、AAAA、MX、NS）
   - 完整的DNS查询-响应处理
   - 添加了 `--turn-server` 和 `--turn-port` 参数支持自定义TURN服务器
   - 命令行参数支持

4. **http_turn_client.py** (新增):
   - 通过TCP TURN转发HTTP/1.1和HTTP/2请求
   - 支持HTTPS（SSL/TLS）连接
   - 完整的HTTP请求-响应处理
   - 支持多种HTTP方法（GET、POST等）
   - 支持自定义HTTP头部和请求体
   - 支持将响应保存到文件
   - 命令行参数支持

5. **http3_turn_client.py** (新增):
   - 通过UDP TURN转发HTTP/3请求
   - 使用QUIC协议进行通信
   - 简化的QUIC和TLS实现
   - 支持HTTP/3请求-响应处理
   - 命令行参数支持
   - 注意：这是简化实现，生产环境需要完整的QUIC协议栈

这些修改使得所有客户端都更加灵活，可以通过命令行参数动态指定目标服务器、TURN服务器和相关参数，而不需要修改源代码。现在支持使用域名或IP地址连接到TURN服务器。

## 文件列表

- `turn_client.py` - 基础TURN客户端（UDP/TCP）
- `smtp_turn_client.py` - SMTP邮件客户端通过TURN
- `dns_turn_client.py` - DNS查询客户端通过TURN
- `http_turn_client.py` - HTTP/1.1和HTTP/2客户端通过TURN
- `http3_turn_client.py` - HTTP/3客户端通过TURN
