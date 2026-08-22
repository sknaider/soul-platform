@echo off
setlocal
title Instalador SOUL Platform

set "SOUL_INSTALLER=%~dp0Install-Soul.ps1"
set "SOUL_DNI_CREDENTIAL_FILE=%~dp0soul-dni.json"
set "SOUL_DNI_TRUST_FILE=%~dp0soul-dni-trust.json"
set "SOUL_DNI_SHA_FILE=%~dp0soul-dni-trust.sha256"
if not exist "%SOUL_INSTALLER%" (
  echo [SOUL] Falta Install-Soul.ps1 junto a este archivo.
  pause
  exit /b 2
)

set "SOUL_DNI_ARGS="
set /a SOUL_DNI_FILES=0
if exist "%SOUL_DNI_CREDENTIAL_FILE%" set /a SOUL_DNI_FILES+=1
if exist "%SOUL_DNI_TRUST_FILE%" set /a SOUL_DNI_FILES+=1
if exist "%SOUL_DNI_SHA_FILE%" set /a SOUL_DNI_FILES+=1
if not "%SOUL_DNI_FILES%"=="0" if not "%SOUL_DNI_FILES%"=="3" (
  echo [SOUL] DNI incompleto junto al instalador. Se requieren los tres archivos publicos.
  pause
  exit /b 2
)
if "%SOUL_DNI_FILES%"=="3" (
  set "SOUL_DNI_ARGS=-DniCredential "%SOUL_DNI_CREDENTIAL_FILE%" -DniTrustStore "%SOUL_DNI_TRUST_FILE%" -DniTrustStoreSha256File "%SOUL_DNI_SHA_FILE%""
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SOUL_INSTALLER%" -RequireBundledWheel %SOUL_DNI_ARGS% %*
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
