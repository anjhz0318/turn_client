# TURN Client Security Toolkit

这个项目是一组用于 TURN/STUN 服务能力验证、安全测试和协议转发实验的 Python 工具。代码主要用于授权环境中的 TURN 服务器评估，包括 UDP/TCP TURN 分配、CreatePermission、ChannelBind、ChannelData 转发、协议转发测试、WebRTC 相关发现，以及特定 DoS 风险的实验性 PoC。

> 仅在你拥有授权的实验环境、内网靶场或自有 TURN 服务上运行这些工具。部分脚本会创建大量 allocation、扫描端口或通过 TURN 转发流量，可能影响服务可用性或触发安全告警。

## 目录概览

| 路径 | 说明 |
| --- | --- |
| `turn_utils/turn_client.py` | TURN/STUN 核心实现，负责报文构造、认证、Allocate、CreatePermission、ChannelBind、ChannelData、TCP TURN 等能力。 |
| `turn_utils/test_turn_capabilities.py` | TURN 能力测试封装，提供长凭据/短凭据回退逻辑。 |
| `turn_dos_poc_attack1.py` | DoS 风险 PoC：持续申请 UDP relay allocation，并刷新保持 allocation 存活，用于验证 relay 端口或配额耗尽风险。 |
| `turn_dos_poc_victim.py` | 正常用户行为模拟：创建 UDP allocation，通过 TURN channel 向 DNS 服务器发送查询。 |
| `comprehensive_udp_turn_tester.py` | UDP TURN 转发综合测试。 |
| `comprehensive_tcp_turn_tester.py` | TCP TURN 转发综合测试。 |
| `no_auth_turn_tester.py` | 无认证 TURN 暴露风险测试。 |
| `cluster_credential_test.py` | 集群中多节点/多端口的凭据和 allocation 能力测试。 |
| `protocol_forwarding/` | HTTP、DNS、SSH、XMPP、gRPC、SMTP、FTP 等协议经 TURN 转发的测试客户端。 |
| `ip_space_scanner/` | 通过 TURN 进行 IP 空间连通性扫描的实验工具。 |
| `webrtc_scanner/` | WebRTC 相关域名发现和页面元素提取工具。 |
| `ip_files/`, `port_files/` | 常用测试 IP/端口列表。 |
| `RFC docs/` | 本项目参考的 STUN/TURN 相关 RFC 文档。 |

## 环境准备

建议使用 Python 3.10+。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

如果只运行基础 TURN 客户端，核心依赖主要是 `dnspython`；WebRTC 扫描相关脚本还会使用 `requests`、`beautifulsoup4`、`python-dotenv` 等。

## 配置

默认 TURN 配置集中在 `config.py`：

```python
DEFAULT_TURN_SERVER = "157.230.175.178"
DEFAULT_TURN_PORT = 3478
USERNAME = "demo"
PASSWORD = "xxx"
REALM = "anjhz3.com"
```

多数脚本也支持通过命令行参数覆盖这些值，例如：

```bash
python3 turn_utils/test_turn_capabilities.py \
  --turn-server 127.0.0.1 \
  --turn-port 3478 \
  --username demo \
  --password 'password' \
  --realm example.org \
  --test-udp
```

## 重点脚本

### `turn_dos_poc_attack1.py`

用途：在授权实验环境中验证 TURN 服务器是否容易被大量 UDP allocation 占满 relay 端口或用户配额。

核心行为：

- 为每次 allocation 绑定一个本地 UDP 端口，保持 5-tuple 稳定。
- 先尝试长期凭据，失败后尝试短期凭据。
- 统计成功 allocation、失败次数、486 Allocation Quota Reached、活跃 allocation 数量。
- allocation 阶段停止后，继续对已成功的 allocation 发送 Refresh，观察服务是否会长期保持资源占用。
- 记录 `XOR-RELAYED-ADDRESS`，用于发现重复 relay 端口分配。

低强度实验示例：

```bash
python3 turn_dos_poc_attack1.py \
  --turn-server 127.0.0.1 \
  --turn-port 3478 \
  --username demo \
  --password 'password' \
  --realm example.org \
  --concurrent 1 \
  --failure-threshold 3 \
  --refresh-interval 300 \
  --monitor-interval 5
```

停止方式：按 `Ctrl+C`，脚本会尝试关闭活跃 socket 并停止 refresh 线程。

注意事项：

- 不要在生产 TURN 服务或第三方目标上运行。
- `--concurrent` 和 `--failure-threshold` 会直接影响请求强度。
- 当前脚本主要关注 UDP allocation，不覆盖 TCP allocation 的资源耗尽路径。

### `turn_dos_poc_victim.py`

用途：模拟正常用户通过 TURN 访问 DNS 服务，常用于和 `turn_dos_poc_attack1.py` 配合观察攻击前后正常用户是否还能申请 relay 并完成转发。

核心行为：

- 创建 UDP TURN allocation。
- 对 DNS 服务器创建 permission。
- 绑定 ChannelData 通道。
- 构造并发送 DNS 查询。
- 接收 ChannelData 响应并解析 DNS answer。
- 每轮查询后关闭 allocation，再进入下一轮。

示例：

```bash
python3 turn_dos_poc_victim.py \
  --turn-server 127.0.0.1 \
  --turn-port 3478 \
  --username demo \
  --password 'password' \
  --realm example.org \
  --dns-server 8.8.8.8 \
  --dns-port 53 \
  --domain www.example.com \
  --run-time 120
```

说明：脚本中已有 `refresh_allocation()` 实现，但当前主循环每次 DNS 查询后会关闭 allocation，因此 `--refresh-interval` 参数暂未在主流程中实际发挥作用。

## 常用测试入口

### TURN 基础能力测试

```bash
python3 turn_utils/test_turn_capabilities.py \
  --turn-server 127.0.0.1 \
  --turn-port 3478 \
  --username demo \
  --password 'password' \
  --realm example.org \
  --target-ip 8.8.8.8 \
  --target-port 53
```

### 标准能力测试

```bash
python3 standard_ability_test.py \
  --turn-server 127.0.0.1 \
  --turn-port 3478 \
  --username demo \
  --password 'password' \
  --realm example.org \
  --domain local-test
```

### UDP/TCP 综合测试

```bash
python3 comprehensive_udp_turn_tester.py \
  --turn-server 127.0.0.1 \
  --turn-port 3478 \
  --username demo \
  --password 'password' \
  --realm example.org

python3 comprehensive_tcp_turn_tester.py \
  --turn-server 127.0.0.1 \
  --turn-port 3478 \
  --username demo \
  --password 'password' \
  --realm example.org
```

## 开发检查

语法检查：

```bash
python3 -m py_compile \
  turn_dos_poc_attack1.py \
  turn_dos_poc_victim.py \
  turn_utils/turn_client.py \
  turn_utils/test_turn_capabilities.py \
  config.py
```

查看脚本参数：

```bash
python3 turn_dos_poc_attack1.py --help
python3 turn_dos_poc_victim.py --help
python3 turn_utils/test_turn_capabilities.py --help
```

## 运行建议

- 先用 `turn_utils/test_turn_capabilities.py` 验证目标 TURN 服务的基础 allocation 和转发能力。
- 再用 `turn_dos_poc_victim.py` 建立正常用户基线，确认 DNS 查询能稳定返回。
- 最后在隔离环境中低并发运行 `turn_dos_poc_attack1.py`，观察 allocation 成功率、486 错误、活跃 allocation 数量，以及 victim 行为是否受影响。
- 所有测试都应记录时间窗口、目标地址、凭据、并发数、服务端日志和脚本输出，便于复现和回滚。

## 已知注意点

- 部分脚本会在日志中打印认证流程、realm、nonce、HMAC key 或响应属性，运行时注意保护输出文件和终端记录。
- `turn_dos_poc_attack1.py` 的 relay 端口重复检测使用进程内累计集合，allocation 释放后的端口复用可能被记录为重复，需要结合时间和服务端日志判断。
- `turn_dos_poc_victim.py` 当前是“每次查询新建 allocation”的模型，不是长连接用户模型。
- 多数脚本主要支持 IPv4；IPv6 场景需要单独验证。

