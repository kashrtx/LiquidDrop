@echo off
rem Prefer the native v5 build; fall back to the Python version.
if exist "%~dp0liquiddrop.exe" ( "%~dp0liquiddrop.exe" %* & exit /b )
if exist "%~dp0target\release\liquiddrop.exe" ( "%~dp0target\release\liquiddrop.exe" %* & exit /b )
python "%~dp0liquiddrop.py" %*
