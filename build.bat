@echo off
chcp 65001 >nul
cd /d "%~dp0"

where py >nul 2>nul
if errorlevel 1 (
    echo Python Launcher не найден.
    echo Установите Python 3.11 или новее и включите Add Python to PATH.
    pause
    exit /b 1
)

py -m pip install --upgrade pip pyinstaller
if errorlevel 1 goto error

py -m PyInstaller --noconfirm --clean --onefile --console --name FoxOffsetFinder fox_offset_finder.py
if errorlevel 1 goto error

echo.
echo Готово: dist\FoxOffsetFinder.exe
pause
exit /b 0

:error
echo.
echo Ошибка сборки.
pause
exit /b 1
