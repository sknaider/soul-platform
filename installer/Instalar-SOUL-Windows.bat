@echo off
setlocal
title Instalador SOUL Platform

set "SOUL_INSTALLER=%~dp0Install-Soul.ps1"
if not exist "%SOUL_INSTALLER%" (
  echo [SOUL] Falta Install-Soul.ps1 junto a este archivo.
  pause
  exit /b 2
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SOUL_INSTALLER%" -RequireBundledWheel %*
set "SOUL_RESULT=%ERRORLEVEL%"
if not "%SOUL_RESULT%"=="0" (
  echo.
  echo [SOUL] La instalacion fallo. Copia el diagnostico de arriba para ADA.
  pause
  exit /b %SOUL_RESULT%
)

echo.
echo [SOUL] Instalacion terminada correctamente.
pause
exit /b 0
