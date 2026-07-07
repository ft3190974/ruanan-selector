# ============================================
# 软安营销平台 - 后端镜像
# 优化：基于 python:slim 精简镜像，仅打包运行必需文件
# ============================================
FROM python:3.11-slim

# 设置时区为北京时间（避免 DB 里 datetime('now','localtime') 与前端展示偏差）
ENV TZ=Asia/Shanghai
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# 系统依赖（仅装最小集，bcrypt 有预编译 wheel 不需要编译工具链）
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

# 先装依赖（利用 Docker 层缓存，代码变动不重装依赖）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 仅复制运行必需的文件（排除 mp4/node_modules/projects 等）
COPY selector_server.py ./
COPY ruanan-marketing-platform.html ./
COPY ruanan-customer-portal.html ./
COPY ruanan-partner-portal.html ./
COPY ruanan-product-selector.html ./
COPY ruanan-product-selector-standalone.html ./
COPY index.html ./
COPY logo.png ./
COPY intro.html outro.html outro_code.html promo_video.html recruit_video.html ./
COPY ruanan-sales-training.html ruanan-tech-website.html ./
COPY test_smoke.py ./

# 数据持久化目录（挂载到宿主机，容器重建不丢数据）
RUN mkdir -p /app/uploads /app/data
VOLUME ["/app/uploads", "/app/data"]

# 环境变量默认值（实际值在 docker-compose.yml 或部署时注入）
ENV ADMIN_PWD="请设置强密码"
ENV ALLOW_INSECURE_ADMIN_PWD=""
ENV CORS_ORIGINS=""

EXPOSE 8081

# tini 作 PID 1，正确处理信号（uvicorn 优雅退出）
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "selector_server:app", "--host", "0.0.0.0", "--port", "8081", "--workers", "2"]
