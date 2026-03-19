---
description: Use the superpowers development workflow for structured feature development with brainstorming, planning, TDD, and code review
---

# Superpowers Development Workflow

This workflow uses the Superpowers skills framework for structured software development.

## Prerequisites

All skills are installed in `.agents/skills/`. Read `using-superpowers/SKILL.md` first.

## Workflow Steps

1. **Brainstorming** — Read and follow `.agents/skills/brainstorming/SKILL.md`
   - Explore project context, ask questions, propose approaches
   - Present design in sections for user approval
   - Save spec document

2. **Writing Plans** — Read and follow `.agents/skills/writing-plans/SKILL.md`
   - Break work into bite-sized TDD tasks (2-5 min each)
   - Include exact file paths, complete code, verification steps
   - Save plan document

3. **Executing Plans** — Read and follow `.agents/skills/executing-plans/SKILL.md`
   - Load plan, review critically, execute tasks
   - Follow TDD cycle: RED → GREEN → REFACTOR
   - Note: Use `executing-plans` instead of `subagent-driven-development` (Antigravity has no subagent support)

4. **Code Review** — Read and follow `.agents/skills/requesting-code-review/SKILL.md`
   - Review against plan after each major step
   - Perform review inline (no subagent dispatch)

5. **Finishing** — Read and follow `.agents/skills/finishing-a-development-branch/SKILL.md`
   - Verify tests pass
   - Present merge/PR/keep/discard options
   - Clean up worktree if applicable

## Supporting Skills (use as needed)

- **`systematic-debugging`** — For any bugs or unexpected behavior
- **`test-driven-development`** — Enforced during implementation
- **`verification-before-completion`** — Before claiming work is done
- **`receiving-code-review`** — When receiving feedback
- **`using-git-worktrees`** — For isolated development branches

## Tool Mapping

See `.agents/skills/using-superpowers/references/antigravity-tools.md` for Claude Code → Antigravity tool equivalents.
