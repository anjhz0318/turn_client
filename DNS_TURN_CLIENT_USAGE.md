# DNS TURN Client 使用说明

## 功能概述

`dns_turn_client.py` 支持两种模式：
1. **单域名查询模式**：查询单个域名
2. **批量测试模式**：从文件读取域名列表，批量测试解析

## 使用方法

### 单域名查询

```bash
python3 protocol_forwarding/dns_turn_client.py \
  --dns-server 168.63.129.16 \
  --dns-port 53 \
  --turn-server 20.202.24.67 \
  --turn-port 443 \
  --username "YOUR_USERNAME" \
  --password "YOUR_PASSWORD" \
  --domain "example.com" \
  --query-type 1 \
  --mode tcp-udp \
  --tls
```

### 批量测试模式

```bash
python3 protocol_forwarding/dns_turn_client.py \
  --dns-server 168.63.129.16 \
  --dns-port 53 \
  --turn-server 20.202.24.67 \
  --turn-port 443 \
  --username "YOUR_USERNAME" \
  --password "YOUR_PASSWORD" \
  --domains-file test_domains.txt \
  --query-type 1 \
  --mode tcp-udp \
  --tls
```

## 域名文件格式

域名文件支持以下格式：
- 每行一个域名
- 以 `#` 开头的行被视为注释
- 空行会被忽略

示例文件 (`test_domains.txt`):
```
# 测试域名列表
management.azure.com
login.microsoftonline.com
privatelink.database.windows.net
www.google.com
```

## 参数说明

- `--dns-server`: DNS服务器IP地址（必需）
- `--dns-port`: DNS服务器端口（默认: 53）
- `--turn-server`: TURN服务器地址（可选）
- `--turn-port`: TURN服务器端口（可选）
- `--username`: TURN服务器用户名（可选）
- `--password`: TURN服务器密码（可选）
- `--realm`: TURN服务器认证域（可选）
- `--domain`: 要查询的域名（单域名查询模式）
- `--domains-file`: 包含域名列表的文件路径（批量测试模式）
- `--query-type`: 查询类型（1=A记录, 28=AAAA记录, 15=MX记录, 2=NS记录，默认: 1）
- `--mode`: TURN模式（udp 或 tcp-udp，默认: udp）
- `--tls`: 使用TLS加密连接
- `--no-reconnect`: 批量测试时不重新连接（默认每个查询都重新连接以提高可靠性）

## 注意事项

1. 批量测试模式默认每个查询都会重新建立TURN连接，以提高可靠性
2. 如果连接稳定，可以使用 `--no-reconnect` 参数提高测试速度
3. 批量测试会显示详细的统计信息，包括成功解析和失败的域名列表
