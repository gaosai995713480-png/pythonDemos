@echo off
setlocal

set "ORIGINAL_LOCAL_DB_USER=%LOCAL_DB_USER%"
set "ORIGINAL_LOCAL_DB_PASSWORD=%LOCAL_DB_PASSWORD%"
set "CREDENTIALS_FILE=C:\Users\xiguasai\.agents\mcp\local-db-credentials.cmd"
if exist "%CREDENTIALS_FILE%" (
  call "%CREDENTIALS_FILE%"
)
if not "%ORIGINAL_LOCAL_DB_USER%"=="" (
  set "LOCAL_DB_USER=%ORIGINAL_LOCAL_DB_USER%"
)
if not "%ORIGINAL_LOCAL_DB_PASSWORD%"=="" (
  set "LOCAL_DB_PASSWORD=%ORIGINAL_LOCAL_DB_PASSWORD%"
)

if "%LOCAL_DB_HOST%"=="" set "LOCAL_DB_HOST=127.0.0.1"
if "%LOCAL_DB_PORT%"=="" set "LOCAL_DB_PORT=3306"
if "%LOCAL_DB_NAME%"=="" set "LOCAL_DB_NAME=love_page"

if "%LOCAL_DB_USER%"=="" (
  echo [ERROR] Missing LOCAL_DB_USER environment variable. 1>&2
  exit /b 1
)

if "%LOCAL_DB_PASSWORD%"=="" (
  echo [ERROR] Missing LOCAL_DB_PASSWORD environment variable. 1>&2
  exit /b 1
)

call C:\Users\xiguasai\.npm_global\universal-db-mcp.cmd --type mysql --host "%LOCAL_DB_HOST%" --port %LOCAL_DB_PORT% --user "%LOCAL_DB_USER%" --password "%LOCAL_DB_PASSWORD%" --database "%LOCAL_DB_NAME%" %*

