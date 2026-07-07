#!/bin/bash
# 软安营销平台 — 腾讯云服务器一键部署脚本
# 用法: ssh root@<IP> 'bash -s' < setup.sh

set -e

echo "=== 1. 安装系统依赖 ==="
apt update && apt install -y python3 python3-pip python3-venv nginx git

echo "=== 2. 克隆代码 ==="
cd /opt
[ -d ruanan-selector ] && cd ruanan-selector && git pull && cd .. || git clone https://github.com/ft3190974/ruanan-selector.git

echo "=== 3. 安装 Python 依赖 ==="
cd /opt/ruanan-selector
pip3 install -r requirements.txt

echo "=== 4. 配置 Nginx ==="
cp deploy/nginx-ruanan.conf /etc/nginx/sites-available/ruanan
ln -sf /etc/nginx/sites-available/ruanan /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo "=== 5. 配置 systemd 服务 ==="
cp deploy/ruanan-api.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable ruanan-api
systemctl restart ruanan-api

echo "=== 6. 完成 ==="
systemctl status ruanan-api --no-pager
echo "部署完成! 访问 http://$(hostname -I | awk '{print $1}')"
