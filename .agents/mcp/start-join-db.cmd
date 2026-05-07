@echo off
setlocal

if "%~1"=="" (
  echo [ERROR] Missing database name argument. 1>&2
  exit /b 1
)

set "JOIN_DATABASE=%~1"
shift

set "ORIGINAL_JOIN_DB_USER=%JOIN_DB_USER%"
set "ORIGINAL_JOIN_DB_PASSWORD=%JOIN_DB_PASSWORD%"
set "CREDENTIALS_FILE=C:\Users\xiguasai\.agents\mcp\db-credentials.cmd"
if exist "%CREDENTIALS_FILE%" (
  call "%CREDENTIALS_FILE%"
)
if not "%ORIGINAL_JOIN_DB_USER%"=="" (
  set "JOIN_DB_USER=%ORIGINAL_JOIN_DB_USER%"
)
if not "%ORIGINAL_JOIN_DB_PASSWORD%"=="" (
  set "JOIN_DB_PASSWORD=%ORIGINAL_JOIN_DB_PASSWORD%"
)

if "%JOIN_DB_USER%"=="" (
  echo [ERROR] Missing JOIN_DB_USER environment variable. 1>&2
  exit /b 1
)

if "%JOIN_DB_PASSWORD%"=="" (
  echo [ERROR] Missing JOIN_DB_PASSWORD environment variable. 1>&2
  exit /b 1
)

call C:\Users\xiguasai\.npm_global\universal-db-mcp.cmd --type mysql --host 10.6.15.22 --port 3306 --user "%JOIN_DB_USER%" --password "%JOIN_DB_PASSWORD%" --database "%JOIN_DATABASE%" %*

