@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "CODEX_BIN_ROOT=%LocalAppData%\OpenAI\Codex\bin"
if not exist "%CODEX_BIN_ROOT%" (
  echo [ERROR] Codex bin root not found: %CODEX_BIN_ROOT% 1>&2
  exit /b 1
)

call :ResolveLatest "node_repl.exe" NODE_REPL_EXE
if errorlevel 1 exit /b 1

if "%NODE_REPL_NODE_PATH%"=="" (
  call :ResolveLatest "node.exe" NODE_EXE
  if errorlevel 1 exit /b 1
  set "NODE_REPL_NODE_PATH=!NODE_EXE!"
)

if "%CODEX_CLI_PATH%"=="" (
  call :ResolveLatest "codex.exe" CODEX_EXE
  if errorlevel 1 exit /b 1
  set "CODEX_CLI_PATH=!CODEX_EXE!"
)

if /i "%~1"=="--print-targets" (
  echo NODE_REPL_EXE=%NODE_REPL_EXE%
  echo NODE_REPL_NODE_PATH=%NODE_REPL_NODE_PATH%
  echo CODEX_CLI_PATH=%CODEX_CLI_PATH%
  exit /b 0
)

"%NODE_REPL_EXE%" %*
exit /b %ERRORLEVEL%

:ResolveLatest
setlocal
set "TARGET_NAME=%~1"
set "RESULT="
for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$root=$env:CODEX_BIN_ROOT; $name=$env:TARGET_NAME; $item=Get-ChildItem -LiteralPath $root -Recurse -Filter $name -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName; if($item){ $item }"`) do (
  set "RESULT=%%I"
  goto :resolved
)
:resolved
if not defined RESULT (
  echo [ERROR] Unable to locate %TARGET_NAME% under %CODEX_BIN_ROOT% 1>&2
  exit /b 1
)
endlocal & set "%~2=%RESULT%"
exit /b 0
