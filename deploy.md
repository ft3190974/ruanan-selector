# 软安营销平台 - 腾讯云部署手册

> **本文档给部署执行方（人或 AI）看**。按顺序执行即可完成部署。
> 环境：腾讯云 Ubuntu 22.04 / 2核2G / 公网 IP。

---

## 一、前置信息（部署方需向项目所有者确认）

| 项 | 值 | 说明 |
|---|---|---|
| 服务器公网 IP | ___________ | 浏览器访问用 |
| SSH 登录用户 | `ubuntu` 或 `root` | 腾讯云轻量默认 ubuntu |
| SSH 登录方式 | 密钥 / 密码 | 推荐密钥 |
| GitHub 仓库 | `ft3190794/ruanan-selector` | 代码来源 |
| admin 初始密码 | `Ruanan@2026Secure` | 首次登录后建议改 |

---

## 二、服务器初始化（一次性，约 15 分钟）

SSH 登录服务器后，**按顺序执行**以下命令：

### 2.1 系统更新 + 装基础工具

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git nginx ufw
```

### 2.2 装 Docker + Docker Compose

```bash
# 官方脚本安装（最简）
curl -fsSL https://get.docker.com | sudo sh

# 把当前用户加进 docker 组（免 sudo 调 docker）
sudo usermod -aG docker $USER

# 验证（需要重新登录生效组权限）
newgrp docker
docker --version
docker compose version
```

### 2.3 防火墙（开 80/443/22）

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status
```

⚠️ **腾讯云安全组也要放行 80/443/22**——控制台 → 轻量应用服务器 → 防火墙 → 添加规则。

### 2.4 创建项目目录

```bash
sudo mkdir -p /opt/ruanan
sudo chown $USER:$USER /opt/ruanan
```

---

## 三、拉代码 + 首次部署（约 10 分钟）

### 3.1 Clone 仓库

```bash
cd /opt/ruanan
git clone https://github.com/ft3190794/ruanan-selector.git .
```

> 如果仓库是 private，需要配 GitHub SSH key 或 PAT。

### 3.2 准备数据库

```bash
cd /opt/ruanan
# 容器内的 DB 路径在 ./data/，把现有 selector.db 复制过去
mkdir -p data
cp selector.db data/selector.db
```

> 如果是全新部署（没有历史数据），跳过 cp，启动后服务会自动建表 + seed admin 账号。

### 3.3 修改配置（重要）

编辑 `docker-compose.yml`，**把 `YOUR_SERVER_IP` 改成实际公网 IP**：

```bash
sed -i "s/YOUR_SERVER_IP/你的实际公网IP/g" docker-compose.yml
```

如果 `ADMIN_PWD` 想改，编辑 `docker-compose.yml` 第 20 行。

### 3.4 启动容器

```bash
cd /opt/ruanan
docker compose up -d --build
```

首次构建约 3-5 分钟（拉镜像 + 装依赖）。完成后：

```bash
# 看容器状态
docker compose ps

# 看启动日志（确认有 "Application startup complete"）
docker compose logs -f --tail 50
```

按 `Ctrl+C` 退出日志查看（不会停服务）。

### 3.5 配置 Nginx 反代

```bash
# 复制配置
sudo cp deploy/nginx-docker.conf /etc/nginx/sites-available/ruanan.conf
sudo ln -s /etc/nginx/sites-available/ruanan.conf /etc/nginx/sites-enabled/

# 测试配置语法
sudo nginx -t

# 重载
sudo systemctl reload nginx
sudo systemctl enable nginx
```

### 3.6 验证部署

```bash
# 本地访问（容器）
curl http://localhost:8081/

# 通过 Nginx 访问（公网）
curl http://localhost/
```

然后**用浏览器**访问 `http://你的公网IP/`，应该看到营销平台首页。

---

## 四、GitHub Actions 自动部署配置（推荐）

配置后，每次 `git push origin main`，服务器自动拉代码重建容器。

### 4.1 在服务器生成 SSH 密钥

```bash
ssh-keygen -t ed25519 -C "github-actions-deploy" -f ~/.ssh/github_actions -N ""
cat ~/.ssh/github_actions.pub
```

把输出的**公钥**追加到授权文件：

```bash
cat ~/.ssh/github_actions.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### 4.2 查看私钥（待会贴到 GitHub）

```bash
cat ~/.ssh/github_actions
```

**完整复制**输出的私钥内容（含 `-----BEGIN/END...-----`）。

### 4.3 在 GitHub 配 Secrets

打开仓库 → Settings → Secrets and variables → Actions → New repository secret，添加 3 个：

| Secret 名 | 值 |
|---|---|
| `SERVER_HOST` | 你的服务器公网 IP |
| `SERVER_USER` | `ubuntu`（或你的登录用户） |
| `SSH_PRIVATE_KEY` | 4.2 步复制的完整私钥 |

### 4.4 测试自动部署

随便改一行代码 → commit → push 到 main → 去 GitHub 仓库的 **Actions** 标签页看部署过程。

服务器端验证：

```bash
cd /opt/ruanan
git log -1 --oneline   # 应该是最新的 commit
docker compose ps      # 容器应该刚重启过
```

---

## 五、未来加域名 + HTTPS

申请域名并解析到服务器 IP 后：

### 5.1 申请免费 SSL 证书（Let's Encrypt）

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

certbot 会自动改 Nginx 配置 + 加定时续期。

### 5.2 改 CORS 白名单

编辑 `/opt/ruanan/docker-compose.yml`，把 `CORS_ORIGINS` 加上 `https://yourdomain.com`：

```bash
cd /opt/ruanan
docker compose down && docker compose up -d
```

---

## 六、日常运维命令

```bash
cd /opt/ruanan

# 查看状态
docker compose ps

# 查看实时日志
docker compose logs -f --tail 100

# 重启服务
docker compose restart

# 停止
docker compose down

# 手动更新（不用 GitHub Actions）
git pull && docker compose up -d --build

# 进入容器调试
docker compose exec app bash

# 备份数据库
cp data/selector.db data/selector.db.bak.$(date +%Y%m%d)

# 清理旧镜像（释放磁盘）
docker image prune -f
```

---

## 七、故障排查

### 问题：浏览器访问 IP 打不开

1. 检查容器是否在跑：`docker compose ps`
2. 检查端口：`curl http://localhost:8081/` 应返回 HTML
3. 检查 Nginx：`curl http://localhost/` 应返回 HTML
4. **腾讯云安全组**是否放行了 80 端口（最常见原因）

### 问题：容器起不来

```bash
docker compose logs --tail 50
```

常见原因：
- `ADMIN_PWD` 是弱密码且 `ALLOW_INSECURE_ADMIN_PWD` 不是 true → 改强密码或设 true
- 端口被占用 → `sudo lsof -i:8081`
- 内存不足（2G 服务器）→ `free -m` 查看，必要时调小 `mem_limit`

### 问题：数据库只读 / 锁定

SQLite WAL 模式下偶尔出现。重启容器通常解决：

```bash
docker compose restart
```

### 问题：上传文件丢失

uploads 目录必须挂载到宿主机。检查 `docker-compose.yml` 里 volumes 是否正确，以及 `/opt/ruanan/uploads/` 是否有写权限。

---

## 八、2核2G 资源优化说明

| 配置 | 值 | 说明 |
|---|---|---|
| uvicorn workers | 2 | 与 CPU 核数匹配 |
| 容器内存上限 | 1500M | 留 500M 给系统 + Nginx |
| Docker 日志 | 10M×3 | 防日志撑爆磁盘 |
| Nginx 静态文件缓存 | 7 天 | uploads 绕过后端 |

**监控内存**：

```bash
free -m
docker stats
```

如果内存吃紧，考虑升级到 2核4G 或换 MySQL（SQLite 在高并发写时锁全库）。

---

## 九、给部署 AI（deepseek）的执行清单

按此顺序执行，每步验证后再下一步：

- [ ] 2.1-2.4 服务器初始化（apt/docker/ufw/目录）
- [ ] 3.1 clone 仓库到 /opt/ruanan
- [ ] 3.2 准备数据库（cp selector.db data/）
- [ ] 3.3 改 docker-compose.yml 里的 IP 和密码
- [ ] 3.4 docker compose up -d --build，确认容器在跑
- [ ] 3.5 配 Nginx，nginx -t 通过
- [ ] 3.6 浏览器访问 IP 验证首页
- [ ] 4.1-4.3 配 GitHub Actions（如需自动部署）
- [ ] 验证 push 触发自动部署

**遇到任何步骤失败，先看日志（docker compose logs / nginx error log）再决策。**
