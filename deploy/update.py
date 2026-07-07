"""软安营销平台 - 一键更新脚本
用法: python deploy/update.py [文件1] [文件2] ...
不传参数则更新所有核心文件
"""
import paramiko, os, sys

HOST = "43.139.114.76"
USER = "root"
PWD = "changle123"
LOCAL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REMOTE = "/opt/ruanan"

CORE_FILES = [
    "selector_server.py",
    "requirements.txt",
    "ruanan-marketing-platform.html",
    "ruanan-product-selector.html",
    "ruanan-customer-portal.html",
    "ruanan-partner-portal.html",
    "ruanan-sales-training.html",
    "ruanan-tech-website.html",
    "index.html",
    "intro.html", "outro.html", "outro_code.html",
    "promo_video.html", "recruit_video.html",
    "ruanan-product-selector-standalone.html",
]

files = sys.argv[1:] if len(sys.argv) > 1 else CORE_FILES

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PWD, timeout=15)
sftp = c.open_sftp()

print(f"更新 {len(files)} 个文件到 {HOST}...")
for f in files:
    src = os.path.join(LOCAL, f)
    dst = f"{REMOTE}/{f}"
    if not os.path.exists(src):
        print(f"SKIP {f} (不存在)")
        continue
    sftp.put(src, dst)
    print(f"OK  {f}")

sftp.close()

# 重启后端
stdin, stdout, stderr = c.exec_command("systemctl restart ruanan-api && sleep 1 && systemctl status ruanan-api --no-pager | head -4")
print("\n" + stdout.read().decode())
c.close()
print("更新完成!")
