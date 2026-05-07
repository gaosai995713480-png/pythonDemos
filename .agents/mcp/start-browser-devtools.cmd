@echo off
setlocal

set "NPM_CONFIG_CACHE=C:\Users\xiguasai\.agents\tmp\npm-cache"
if not exist "%NPM_CONFIG_CACHE%" mkdir "%NPM_CONFIG_CACHE%"

npx -y chrome-devtools-mcp@latest %*

