#!/bin/bash
# 启动 WebRTC 域名扫描脚本的后台任务脚本

# 进入脚本目录
cd "$(dirname "$0")"

# 设置日志文件
LOG_FILE="scanner_$(date +%Y%m%d_%H%M%S).log"

echo "启动 WebRTC 域名扫描脚本..."
echo "日志文件: $LOG_FILE"
echo "使用 10 个线程"

# 使用 nohup 在后台运行，并将输出重定向到日志文件
nohup python3 webrtc_domain_scanner.py \
    --threads 10 \
    --delay 1 \
    >> "$LOG_FILE" 2>&1 &

# 获取进程 ID
PID=$!
echo "脚本已在后台启动，进程 ID: $PID"
echo "查看日志: tail -f $LOG_FILE"
echo "停止脚本: kill $PID"
echo "检查进度: python3 -c \"import json; f=open('webrtc_scan_progress.json'); print(json.load(f))\""

# 将 PID 保存到文件
echo $PID > scanner.pid
echo "进程 ID 已保存到 scanner.pid"

