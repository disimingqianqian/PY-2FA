@echo off
chcp 936 >nul
"Python" -m pip install -r requirements.txt -i https://mirrors.huaweicloud.com/repository/pypi/simple
echo 代码执行完成,请查看输出
pause >nul