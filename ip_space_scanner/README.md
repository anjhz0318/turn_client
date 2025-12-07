# TURN IP地址空间扫描工具

用于扫描互联网IPv4地址空间，发现TURN服务器的工具。

## 功能特性

1. **多端口扫描**：
   - UDP 3478端口（标准TURN端口）
   - TCP 443端口（TLS/纯TCP）
   - TCP 5349端口（TLS/纯TCP）

2. **智能TLS检测**：
   - 先尝试TLS连接
   - 如果TLS失败，自动回退到纯TCP

3. **信息收集**：
   - Realm信息
   - Banner（SOFTWARE属性）
   - TLS证书域名
   - 反向DNS（rDNS）
   - WHOIS信息

4. **扫描模式**：
   - 单IP测试模式
   - 全IPv4地址空间扫描模式

5. **多线程支持**：
   - 支持多线程并发扫描
   - 实时保存结果到JSON文件

## 使用方法

### 单IP测试模式

测试单个IP地址：

```bash
python3 turn_ip_scanner.py --ip 8.8.8.8
```

### 全IPv4扫描模式

扫描所有IPv4地址空间（约42亿个IP）：

```bash
python3 turn_ip_scanner.py --scan-all --threads 20 --output results.json
```

**注意**：全IPv4扫描需要非常长的时间，建议使用大量线程和足够的存储空间。

### 参数说明

- `--ip IP地址`: 测试单个IP地址
- `--scan-all`: 扫描所有IPv4地址空间
- `--output 文件路径`: 输出JSON文件路径（默认：`turn_scan_results.json`）
- `--threads 线程数`: 线程数（默认：10）

## 输出格式

结果以JSON格式保存，每个IP地址包含以下信息：

```json
{
  "8.8.8.8": {
    "ip": "8.8.8.8",
    "timestamp": "2024-01-01T12:00:00",
    "udp_3478": {
      "port": 3478,
      "protocol": "UDP",
      "success": false,
      "realm": "example.com",
      "banner": "coturn-4.5.2",
      "error": "401 Unauthorized"
    },
    "tcp_443": {
      "port": 443,
      "protocol": "TCP",
      "tls": true,
      "success": false,
      "realm": "example.com",
      "banner": "coturn-4.5.2",
      "tls_cert_domains": ["turn.example.com", "*.example.com"],
      "error": "401 Unauthorized"
    },
    "tcp_5349": null,
    "rdns": "dns.google",
    "whois": {
      "raw": "whois information..."
    }
  }
}
```

## 注意事项

1. **扫描速度**：全IPv4扫描非常耗时，建议：
   - 使用大量线程（20-100+）
   - 在性能强大的服务器上运行
   - 确保有足够的网络带宽

2. **存储空间**：扫描结果可能占用大量存储空间，建议：
   - 定期备份结果文件
   - 使用压缩存储

3. **网络限制**：
   - 某些网络可能限制扫描行为
   - 建议在合法授权的网络环境中使用

4. **资源消耗**：
   - 扫描会消耗大量CPU和网络资源
   - 建议在专用服务器上运行

## 依赖

- Python 3.6+
- `whois` 命令（用于查询WHOIS信息）
- 项目中的 `turn_utils` 模块

## 示例

### 测试单个IP

```bash
$ python3 turn_ip_scanner.py --ip 157.230.175.178
[*] 扫描 157.230.175.178...
[+] 发现TURN服务器: 157.230.175.178

======================================================================
📊 扫描结果
======================================================================
{
  "ip": "157.230.175.178",
  "timestamp": "2024-01-01T12:00:00",
  "udp_3478": {
    "port": 3478,
    "protocol": "UDP",
    "success": false,
    "realm": "default",
    "banner": "coturn-4.5.2",
    "error": "401 Unauthorized"
  },
  ...
}
```

### 开始全IPv4扫描

```bash
$ python3 turn_ip_scanner.py --scan-all --threads 50 --output turn_servers.json
[+] 开始扫描所有IPv4地址空间...
[+] 使用 50 个线程
[+] 总共需要扫描 4294967296 个IP地址
[*] 进度: 1000/4294967296 (0.00%), 已发现: 2
[+] 已发现 3 个TURN服务器
...
```

