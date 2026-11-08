
@echo off
setlocal

echo Building P2P File Transfer...

if not exist build mkdir build

cl /nologo /std:c++17 /O2 /EHsc /W4 /utf-8 main.cpp /Fe:build\P2PTransfer.exe Ws2_32.lib Bcrypt.lib

if errorlevel 1 (
    echo.
    echo BUILD FAILED
    pause
    exit /b 1
)

echo.
echo BUILD SUCCESSFUL
echo Output: build\P2PTransfer.exe

pause
