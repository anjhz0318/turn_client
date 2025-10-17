# TURN客户端配置文件使用说明

## 配置文件概述

`config.py` 是TURN客户端项目的集中配置文件，包含了所有TURN服务器连接信息和认证凭据。

## 主要配置项

### TURN服务器配置
```python
DEFAULT_TURN_SERVER = "157.230.175.178"  # TURN服务器IP地址
DEFAULT_TURN_PORT = 3478                  # TURN服务器端口
```

### 认证信息
```python
USERNAME = "demo"           # TURN服务器用户名
PASSWORD = "demoPass123"    # TURN服务器密码
REALM = "anjhz3.com"       # 认证域
```

### 其他配置
```python
DEFAULT_TIMEOUT = 10                    # 默认超时时间（秒）
DEFAULT_BUFFER_SIZE = 4096              # 默认缓冲区大小
DEFAULT_CHANNEL_NUMBER = 0x4000         # 默认通道号
```

## 使用方法

### 1. 修改TURN服务器配置

如果需要使用不同的TURN服务器，只需修改 `config.py` 文件：

```python
# 修改TURN服务器地址
DEFAULT_TURN_SERVER = "your-turn-server.com"
DEFAULT_TURN_PORT = 3478

# 修改认证信息
USERNAME = "your-username"
PASSWORD = "your-password"
REALM = "your-realm.com"
```

### 2. 验证配置

运行配置文件来验证配置是否正确：

```bash
python3 config.py
```

输出示例：
```
✅ 配置验证通过
TURN服务器: 157.230.175.178:3478
用户名: demo
认证域: anjhz3.com
```

### 3. 使用客户端

所有客户端现在都会自动使用配置文件中的设置：

```bash
# HTTP客户端
python3 http_turn_client.py --target-host httpbin.org --method GET --path /get

# DNS客户端
python3 dns_turn_client.py --dns-server 8.8.8.8 --domain www.google.com

# FTP客户端
python3 ftp_turn_client.py test

# 基础TURN客户端
python3 turn_client.py udp --target-ip 8.8.8.8 --target-port 53
```

## 配置文件功能

### 配置验证
配置文件包含自动验证功能，确保：
- TURN服务器地址不为空
- 端口号在有效范围内（1-65535）
- 认证信息完整
- 通道号在有效范围内（0x4000-0x4FFF）

### 辅助函数
配置文件提供了多个辅助函数：

```python
# 获取TURN配置
config = get_turn_config()

# 获取测试服务器配置
http_config = get_test_server("http")

# 获取协议默认端口
port = get_protocol_port("HTTP")  # 返回 80

# 获取DNS查询类型
query_type = get_dns_query_type("A")  # 返回 1

# 获取HTTP状态消息
message = get_http_status_message(200)  # 返回 "OK"
```

### 测试服务器配置
配置文件包含了各种协议的测试服务器：

```python
TEST_SERVERS = {
    "http": {
        "host": "httpbin.org",
        "port": 80,
        "https_port": 443
    },
    "dns": {
        "host": "8.8.8.8",
        "port": 53
    },
    "ftp": {
        "host": "test.rebex.net",
        "port": 21,
        "username": "demo",
        "password": "password"
    }
}
```

## 优势

1. **集中管理**: 所有配置信息集中在一个文件中
2. **易于维护**: 修改配置只需编辑一个文件
3. **自动验证**: 配置验证确保设置正确
4. **类型安全**: 提供类型检查和默认值
5. **扩展性**: 易于添加新的配置项和功能

## 注意事项

1. **安全性**: 配置文件包含敏感信息（密码），请确保文件权限设置正确
2. **备份**: 修改配置前建议备份原文件
3. **验证**: 修改配置后运行 `python3 config.py` 验证配置
4. **兼容性**: 所有客户端都支持命令行参数覆盖配置文件设置

## 示例：使用自定义TURN服务器

```bash
# 方法1：修改config.py文件
# 编辑config.py，修改DEFAULT_TURN_SERVER等配置

# 方法2：使用命令行参数覆盖
python3 http_turn_client.py \
  --target-host httpbin.org \
  --turn-server your-server.com \
  --turn-port 3478 \
  --method GET \
  --path /get
```

配置文件的使用使得TURN客户端项目更加灵活和易于维护！

