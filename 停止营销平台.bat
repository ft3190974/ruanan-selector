@echo off
chcp 65001 >nul
echo 正在停止营销平台...

REM 查找并终止占用 8081 端口的进程
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8081" ^| findstr "LISTENING"') do (
    echo 终止进程 PID: %%a
    taskkill /PID %%a /F >nul 2>&1
)

REM 同时清理 pythonw 进程中运行 selector_server 的
wmic process where "name='pythonw.exe' and commandline like '%%selector_server%%'" call terminate >nul 2>&1

echo.
echo 营销平台已停止。
pause
