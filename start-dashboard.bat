@echo off
title netmapper

rem Run from wherever this file lives, on any drive or folder (/d switches drive).
cd /d "%~dp0"

rem Roomy starting window so the dashboard isn't clipped (it also auto-fits the terminal).
mode con: cols=112 lines=48

rem Find Python: prefer "python" on PATH, fall back to the Windows "py" launcher.
set "PY=python"
where python >nul 2>nul || set "PY=py"
where %PY% >nul 2>nul || goto :nopython

%PY% -m netmapper
goto :done

:nopython
echo.
echo   Python 3 was not found on this computer.
echo   Install it from https://www.python.org/downloads/
echo   (tick "Add Python to PATH" during setup), then run this again.
echo.

:done
echo.
echo netmapper closed. Press any key to close this window.
pause >nul
