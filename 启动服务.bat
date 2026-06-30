@echo off
echo ============================================
echo   软安科技 · 本地服务一键启动
echo ============================================
echo.

set PYTHON=C:\Program Files\Python314\python.exe

echo [1/2] 启动 CRA合规平台 (端口 8080)...
start "CRA合规平台-8080" cmd /c "cd /d C:\Users\常乐\Desktop\cra-platform\backend && set CRA_ALLOW_INSECURE_SECRET=true && %PYTHON% -m uvicorn app.main:app --host 127.0.0.1 --port 8080"

echo [2/2] 启动 营销管理平台 (端口 8081)...
start "营销平台-8081" cmd /c "cd /d C:\Users\常乐\Desktop\软安科技 && set ALLOW_INSECURE_ADMIN_PWD=true && %PYTHON% -m uvicorn selector_server:app --host 127.0.0.1 --port 8081"

echo.
echo ============================================
echo   服务启动中，请稍候...
echo.
echo   CRA合规平台:  http://localhost:8080
echo   营销管理平台:  http://localhost:8081
echo ============================================
echo.
timeout /t 5 >nul
start http://localhost:8080
start http://localhost:8081
