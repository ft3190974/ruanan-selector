' 软安营销平台 — 后台常驻启动脚本
' 双击运行即可，进程在后台持续运行（无窗口）
' 停止方式：双击「停止营销平台.bat」或任务管理器结束 python.exe

Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' 用 PowerShell Start-Process 后台启动（Hidden 窗口，环境变量通过 PS 注入）
psCmd = "powershell -ExecutionPolicy Bypass -Command ""$env:ALLOW_INSECURE_ADMIN_PWD='true';" & _
        "$env:CORS_ORIGINS='http://localhost:8081,http://127.0.0.1:8081';" & _
        "Start-Process -FilePath 'python' -ArgumentList '-m','uvicorn','selector_server:app','--host','127.0.0.1','--port','8081'" & _
        " -WorkingDirectory '" & scriptDir & "' -WindowStyle Hidden" & _
        " -RedirectStandardOutput '" & scriptDir & "\server.log'" & _
        " -RedirectStandardError '" & scriptDir & "\server.err'"""

WshShell.Run psCmd, 0, False

' 等待 4 秒让服务启动
WScript.Sleep 4000

MsgBox "营销平台已在后台启动！" & vbCrLf & vbCrLf & _
       "访问地址：http://localhost:8081/ruanan-marketing-platform.html" & vbCrLf & vbCrLf & _
       "停止方式：双击「停止营销平台.bat」" & vbCrLf & _
       "开机自启：已添加到启动文件夹", _
       vbInformation, "营销平台启动成功"
