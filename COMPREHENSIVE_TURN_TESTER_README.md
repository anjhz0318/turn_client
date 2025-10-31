# TURN服务器综合测试脚本使用指南

## 功能特性

1. **DNS解析**：使用`turn_server_discovery.py`解析TURN服务器所有IP地址
2. **能力测试**：测试UDP/TCP-UDP/TCP三种转发能力
3. **内网IP转发测试**：测试常见内网IP的访问能力
4. **断点续测**：支持中断后继续测试，自动跳过已测试内容
5. **多线程**：每个TURN服务器IP使用独立线程测试
6. **实时保存**：每次测试后立即保存结果
7. **连接复用模式**：支持复用控制连接，为每个IP建立一次TURN连接测试所有端口

## 使用方法

### 基本用法

```bash
python3 comprehensive_turn_tester.py \
  --turn-server example.turn.server \
  --turn-port 3478 \
  --username "your_username" \
  --password "your_password" \
  --output results.json
```

### 使用TLS

```bash
python3 comprehensive_turn_tester.py \
  --turn-server singapore.turn.twilio.com \
  --turn-port 443 \
  --username "user:pass" \
  --password "secret" \
  --tls
```

### 指定线程数和认证域

```bash
python3 comprehensive_turn_tester.py \
  --turn-server rtc.peercalls.com \
  --turn-port 3478 \
  --username "1761553102:peercalls" \
  --password "4ZfiNiOBz/52bhLd0jiHse9VomM=" \
  --realm "peercalls.com" \
  --threads 8 \
  --output peercalls_test.json
```

### 连接复用模式

**默认行为（启用连接复用）**：
```bash
python3 comprehensive_turn_tester.py \
  --turn-server example.turn.server \
  --turn-port 3478 \
  --username "user" \
  --password "pass" \
  --reuse-connection \
  --threads 4
```

此模式下，为每个目标IP建立**一次**TURN控制连接，然后复用该连接测试该IP的所有端口，可显著提升测试速度。

**禁用连接复用**（为每个端口建立新连接）：
```bash
python3 comprehensive_turn_tester.py \
  --turn-server example.turn.server \
  --turn-port 3478 \
  --username "user" \
  --password "pass" \
  --no-reuse-connection
```

此模式下，每个端口测试都会建立独立的TURN连接，速度较慢但更稳定，适合某些对连接状态敏感的场景。

## 配置文件

### standard_test_ips.txt

定义要测试的内网IP地址列表：
```
192.168.1.1
192.168.0.1
172.16.0.1
10.0.0.1
172.18.0.1
127.0.0.1
169.254.169.254
```

### standard_test_ports.txt

定义要测试的端口列表（从端口80开始测试）：
```
22
443
3389
1433
3306
6379
8080
8443
5900
```

## 输出结果格式

```json
{
  "turn.example.com": {
    "192.168.1.100": {
      "metadata": {
        "turn_port": 3478,
        "username": "test_user",
        "discovery_timestamp": "2024-01-01T00:00:00"
      },
      "capabilities": {
        "udp": true,
        "tcp_udp": true,
        "tcp": true
      },
      "tested_targets": {
        "192.168.1.1": {
          "ports": {
            "80": {
              "port": 80,
              "timestamp": "2024-01-01T00:00:01",
              "permission_denied": false,
              "connection_success": false,
              "error": "Connection failed"
            }
          },
          "timestamp": "2024-01-01T00:00:00"
        },
        "172.16.0.1": {
          "permission_denied": true,
          "ports": {
            "80": {
              "permission_denied": true
            }
          }
        }
      }
    },
    "192.168.1.101": {
      "metadata": {
        "turn_port": 3478,
        "username": "test_user",
        "discovery_timestamp": "2024-01-01T00:00:00"
      },
      "capabilities": {
        "udp": true,
        "tcp": false
      },
      "tested_targets": {}
    }
  }
}
```

## 工作流程

1. **DNS发现**：解析TURN服务器所有IP地址
2. **能力测试**：对每个IP测试UDP/TCP-UDP/TCP能力
3. **内网测试**（仅限TCP能力）：
   - **连接复用模式（默认）**：
     - 为每个目标IP建立一次TURN控制连接
     - 复用该连接测试该IP的所有端口
     - 测试完成后关闭连接
     - 优势：速度快，减少TURN服务器负载
   - **独立连接模式**：
     - 为每个端口测试建立新的TURN连接
     - 优势：更稳定，适合对连接状态敏感的场景
   - 如果端口80权限被拒绝，跳过该IP的后续端口
   - 每个端口测试后立即保存结果

## 断点续测

如果测试中断，重新运行相同命令即可自动继续：
- 跳过已测试的目标IP
- 保留已完成的测试结果
- 自动继续未完成的测试

## 示例

### 测试Metered TURN

```bash
python3 comprehensive_turn_tester.py \
  --turn-server global.relay.metered.ca \
  --turn-port 80 \
  --username "5e79568cd8adbad21e8ea62b" \
  --password "qZWKRJVh3HXFtQjd" \
  --output metered_comprehensive_test.json
```

### 测试Twilio TURN

```bash
python3 comprehensive_turn_tester.py \
  --turn-server singapore.turn.twilio.com \
  --turn-port 443 \
  --username "811b9212d3ae7ee9024482517d036c9b3912139c3d96cbc08eff8f7a9e848ce2" \
  --password "bZfrD47srNug5Hcvn1Xju9C12NBgP4ZHFgNcPAx5sJ8=" \
  --tls \
  --output twilio_comprehensive_test.json
```

### 测试PeerCalls TURN

```bash
python3 comprehensive_turn_tester.py \
  --turn-server rtc.peercalls.com \
  --turn-port 3478 \
  --username "1761633023:peercalls" \
  --password "VEWSvH4t+6MjcwMMN/aH37aCQnA=" \
  --realm "peercalls.com" \
  --output peercalls_comprehensive_test.json
```

## 性能调优

- 默认4线程，可根据网络情况调整
- **连接复用模式**（默认）：为每个IP建立一次连接，测试所有端口，速度快
- **独立连接模式**：每个端口建立新连接，速度慢但更稳定
- 内网测试可能较慢（每个端口约30秒超时）
- 建议在网络稳定环境下运行

## 注意事项

1. 测试需要合法的TURN服务器凭据
2. 内网IP测试仅在有TCP能力时进行
3. 端口80测试失败（权限被拒绝）会跳过该IP的后续端口
4. 输出文件会自动保存，支持断点续测

## 故障排除

### DNS解析失败
- 检查TURN服务器域名是否正确
- 检查网络连接

### 权限创建失败
- 检查用户名密码是否正确
- 确认认证域(realm)配置

### 测试超时
- 增加网络超时时间（修改代码中的timeout值）
- 检查TURN服务器是否在线

