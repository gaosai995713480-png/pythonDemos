# Antigravity Tool Mapping

Skills use Claude Code tool names. When you encounter these in a skill, use your platform equivalent:

| Skill references | Antigravity equivalent |
|-----------------|----------------------|
| `Read` (file reading) | `view_file` |
| `Write` (file creation) | `write_to_file` |
| `Edit` (file editing) | `replace_file_content` / `multi_replace_file_content` |
| `Bash` (run commands) | `run_command` |
| `Grep` (search file content) | `grep_search` |
| `Glob` (search files by name) | `find_by_name` |
| `TodoWrite` (task tracking) | Update `task.md` artifact (manual checklist in brain directory) |
| `Skill` tool (invoke a skill) | `view_file` on the skill's SKILL.md file |
| `WebSearch` | `search_web` |
| `WebFetch` | `read_url_content` |
| `Task` tool (dispatch subagent) | No general equivalent — see below |

## No general subagent support

Antigravity has no equivalent to Claude Code's `Task` tool for general-purpose subagent dispatch. The `browser_subagent` tool only handles browser-based tasks.

Skills that rely on subagent dispatch (`subagent-driven-development`, `dispatching-parallel-agents`) will **fall back to single-session execution** via `executing-plans`.

For spec review loops and code review in skills like `brainstorming` and `writing-plans`, perform the review inline within the current session rather than dispatching a separate subagent.

## Additional Antigravity tools

These tools are available in Antigravity but have no Claude Code equivalent:

| Tool | Purpose |
|------|---------|
| `list_dir` | List files and subdirectories |
| `generate_image` | Generate images from text prompts |
| `browser_subagent` | Perform browser-based tasks (click, type, navigate) |
| `task_boundary` | Structured task progress tracking in the UI |
| `notify_user` | Communicate with user during task mode |
| `view_content_chunk` | View chunks of URL content |
