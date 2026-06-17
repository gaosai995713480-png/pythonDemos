# MCP PRE 环境接入与数据库 Wrapper 统一 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 Codex / Claude 新增 PRE 数据库 MCP，并把数据库类 MCP 的启动入口统一到共享 wrapper。

**Architecture:** 仅修改全局 MCP 注册配置与管理文档，不碰业务项目代码。Codex 侧统一现有数据库类 `command` 到共享 wrapper，Codex / Claude 两侧同时补齐 PRE 条目，最后更新文档并做配置级校验。

**Tech Stack:** PowerShell、TOML、JSON、Markdown

---

### Task 1: 备份并修改 Codex MCP 配置

**Files:**
- Modify: `C:\Users\xiguasai\.codex\config.toml`
- Create: `C:\Users\xiguasai\.codex\config.toml.bak-pre-20260611-*`

- [ ] **Step 1: 备份原始 Codex 配置**

Run: `Copy-Item 'C:\Users\xiguasai\.codex\config.toml' 'C:\Users\xiguasai\.codex\config.toml.bak-pre-<timestamp>'`
Expected: 生成可回滚备份文件。

- [ ] **Step 2: 统一数据库 MCP wrapper 并新增 PRE 条目**

变更点：
- 将 `db-abc` / `db-bms` / `db-erp` / `db-abc-uat` / `db-bms-uat` / `db-erp-uat` / `universal-db-mcp` 的 `command` 统一为 `C:\Users\xiguasai\.agents\mcp\start-universal-db-mcp.cmd`
- 新增 `db-abc-pre` / `db-bms-pre` / `db-erp-pre`

- [ ] **Step 3: 核对 Codex 配置片段**

Run: `Select-String -Path 'C:\Users\xiguasai\.codex\config.toml' -Pattern 'db-abc-pre|db-bms-pre|db-erp-pre|start-universal-db-mcp.cmd'`
Expected: 能看到 3 个 PRE 条目和统一后的 wrapper 路径。

### Task 2: 修改 Claude MCP 配置

**Files:**
- Modify: `C:\Users\xiguasai\.claude.json`
- Create: `C:\Users\xiguasai\.claude.json.bak-pre-20260611-*`

- [ ] **Step 1: 备份原始 Claude 配置**

Run: `Copy-Item 'C:\Users\xiguasai\.claude.json' 'C:\Users\xiguasai\.claude.json.bak-pre-<timestamp>'`
Expected: 生成可回滚备份文件。

- [ ] **Step 2: 新增 PRE MCP 条目**

变更点：
- 在顶层 `mcpServers` 中新增 `db-abc-pre` / `db-bms-pre` / `db-erp-pre`
- 保持现有数据库类 MCP 的 wrapper 不变，继续使用 `C:\Users\xiguasai\.agents\mcp\start-universal-db-mcp.cmd`

- [ ] **Step 3: 核对 Claude 配置片段**

Run: `Select-String -Path 'C:\Users\xiguasai\.claude.json' -Pattern 'db-abc-pre|db-bms-pre|db-erp-pre|start-universal-db-mcp.cmd'`
Expected: 能看到新增 PRE 条目，且 command 指向统一 wrapper。

### Task 3: 更新 MCP 管理清单并验证

**Files:**
- Modify: `C:\Users\xiguasai\.codex\docs\MCP管理清单.md`

- [ ] **Step 1: 更新文档中的已注册 MCP 列表与说明**

变更点：
- 补充 `db-abc-pre` / `db-bms-pre` / `db-erp-pre`
- 说明数据库环境已覆盖 test / uat / pre
- 明确数据库类 MCP 统一走 `start-universal-db-mcp.cmd`

- [ ] **Step 2: 运行最小配置验证**

Run: `Select-String` / `Get-Content` 检查三份文件中的关键片段，并确认未误改 `node_repl`。
Expected: 只有数据库类 MCP 与文档发生预期变化。

- [ ] **Step 3: 总结变更并提示重启**

输出：
- 变更了哪些 server
- Codex / Claude 需要重启后才会加载新的 MCP 配置
