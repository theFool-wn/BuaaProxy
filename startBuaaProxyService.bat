@echo off
chcp 65001 >nul
echo [%date% %time%] 启动BUAA Proxy服务...

call conda activate BuaaProxy

cd /d D:\ProgramData\PycharmProjects\BuaaProxy

echo 使用Waitress启动服务...
waitress-serve --host=0.0.0.0 --port=5000 BuaaProxy:app

echo [%date% %time%] 服务已退出
pause