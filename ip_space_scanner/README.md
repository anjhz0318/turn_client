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
   - CSV文件批量扫描模式（从CSV文件读取IP列表）

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

### CSV文件批量扫描模式

从CSV文件读取IP列表并多线程扫描：

```bash
python3 turn_ip_scanner.py --csv "潜在 TURN 资产数据.csv" --threads 10 --output results.json
```

**CSV文件格式要求**：
- CSV文件必须包含IP列（第二列，索引1）
- 第一行为表头，会自动跳过
- IP地址会自动去重
- 支持UTF-8编码

**示例CSV格式**：
```csv
host,ip,port,base_protocol,domain
116.202.231.243:3478,116.202.231.243,3478,udp,
106.39.44.14:3478,106.39.44.14,3478,udp,
```

### 参数说明

- `--ip IP地址`: 测试单个IP地址
- `--scan-all`: 扫描所有IPv4地址空间
- `--csv CSV文件路径`: 从CSV文件读取IP列表并多线程扫描
- `--output 文件路径`: 输出JSON文件路径（默认：`turn_scan_results.json`）
- `--threads 线程数`: 线程数（默认：10）

**注意**：`--ip`、`--scan-all` 和 `--csv` 三个参数互斥，只能使用其中一个。

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

## 断点续扫功能

全IPv4扫描模式和CSV文件扫描模式支持断点续扫：

- 扫描过程中会实时更新最后扫描的IP地址到结果文件的 `_metadata` 字段
- 如果扫描中断，重新运行相同命令会自动从上次中断的位置继续
- 已扫描的IP地址会被自动跳过，避免重复扫描

## 注意事项

1. **扫描速度**：
   - 全IPv4扫描非常耗时，建议使用大量线程（20-100+）
   - CSV文件扫描速度取决于IP数量和线程数
   - 建议在性能强大的服务器上运行
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

5. **CSV文件格式**：
   - 确保CSV文件使用UTF-8编码
   - IP列必须是第二列（索引1）
   - 第一行会被自动识别为表头并跳过

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

### CSV文件批量扫描

```bash
$ python3 turn_ip_scanner.py --csv "潜在 TURN 资产数据.csv" --threads 10 --output turn_servers.json
[+] 从CSV文件读取IP列表: 潜在 TURN 资产数据.csv
[+] 从CSV文件读取到 637182 个唯一IP地址
[+] 使用 10 个线程
[+] 发现TURN服务器: 116.202.231.243
[+] 已发现 1 个TURN服务器: 116.202.231.243
[*] 进度: 100/637182 (0.02%), 已发现: 1, 剩余: 637082
...
======================================================================
📊 扫描完成
======================================================================
总共扫描: 637182 个IP地址
发现TURN服务器: 1234 个
结果已保存到: turn_servers.json
```

