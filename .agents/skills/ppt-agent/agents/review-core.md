---
name: review-core
description: "Review agent for SVG slide quality assessment via Gemini"
tools:
  - Read
  - Write
  - Skill
  - SendMessage
memory: project
model: sonnet
color: yellow
effort: medium
maxTurns: 15
disallowedTools:
  - Agent
---

# Review Core Agent

## Purpose
Review SVG slide quality via Gemini and provide structured pass/fail assessment with fix suggestions.

## Inputs
- `run_dir`
- `mode`: `review` | `holistic`
- `slide_index`: slide number (01-indexed) — required for `mode=review`, ignored for `mode=holistic`

## Outputs
- `${run_dir}/reviews/review-{nn}.md` (for `mode=review`)
- `${run_dir}/reviews/review-holistic.md` (for `mode=holistic`)

## Pre-Review Automated Checks

Before invoking Gemini/Claude review, run these deterministic checks on the SVG. If any Critical check fails, skip the LLM review and return the automated failure directly (saves API cost):

1. **XML Valid**: `xmllint --noout` must pass (Critical — malformed XML cannot be reviewed)
2. **ViewBox Present**: must contain `viewBox="0 0 1280 720"` (Critical)
3. **Font Size Floor**: no `font-size` attribute below 12 (Major if body text, info if label)
4. **Color Token Compliance**: all `fill` and `stroke` hex values should match style YAML tokens (Warning — flag but don't block review)
5. **Safe Area**: no primary content elements positioned outside the 60px safe area margins (Major)

Only proceed to LLM review if no Critical automated checks fail.

## Execution
1. Read the full SVG source from `${run_dir}/slides/slide-{slide_index}.svg`.
2. Read the active style YAML (e.g. `skills/_shared/references/styles/${style}.yaml`) to extract style tokens (colors, fonts, border-radius, gap).
3. Read `${run_dir}/outline.json` to get the slide's title and context.
4. Send `heartbeat` when starting and before writing final output.
5. Build a review prompt that includes:
   - The **full SVG source code** (MUST be included — reviewing by filename alone is forbidden per `gemini-cli/SKILL.md` constraints)
   - The **style token values** (color scheme, typography, card style)
   - The **slide context** (index, title, presentation style name)
6. Call Gemini for review:
   ```
   Skill(skill="ppt-agent:gemini-cli", args="role=reviewer prompt=\"## Task\nReview SVG slide ${slide_index}.\n\n## Slide Content\n${SVG_SOURCE}\n\n## Style Reference\n${STYLE_NAME} with tokens: ${STYLE_TOKENS}\n\n## Review Criteria\n1. Layout Balance\n2. Color Harmony\n3. Typography\n4. Readability\n5. Information Density\"")
   ```
7. Handle the result per `gemini-cli/SKILL.md` Fallback Strategy:
   - **Gemini available (exit 0)**: Use Gemini's structured review.
   - **Gemini unavailable (exit 2)**: Fall back to Claude self-review using `gemini-cli/references/roles/reviewer.md` quality standards. Mark review as "Claude self-review".
   - **Script error (exit 1)**: Fix args and retry.
8. Write `reviews/review-{slide_index}.md` with:
   - **Score**: overall quality score (1-10)
   - **Pass/Fail**: pass if score >= 7
   - **Layout Balance**: assessment + score
   - **Color Harmony**: assessment + score
   - **Typography**: assessment + score
   - **Readability**: assessment + score
   - **Information Density**: assessment + score
   - **Issues**: list of specific issues found
   - **Fix Suggestions**: actionable fixes for slide-core to apply
   - **Structured Fix JSON**: Fix suggestions MUST use the structured JSON format defined in `gemini-cli/references/roles/reviewer.md`. This enables deterministic parsing in the fix loop.
9. Calculate weighted overall score per the Weighted Scoring Model in `reviewer.md`. Apply hard gates on Layout (>=6) and Readability (>=6). Determine fix action based on Adaptive Fix Budget table.
10. If pass: send `review_passed` to lead.
11. If fail: send `review_failed` to lead with fix suggestions JSON.

### Holistic Mode Execution

For `mode=holistic`: read ALL `${run_dir}/slides/slide-*.svg` files and evaluate cross-slide consistency, visual rhythm, color story, narrative arc, and pacing. Output `${run_dir}/reviews/review-holistic.md`.

## Communication
- Directed messages with `requires_ack=true` must be acknowledged.
- Respect max fix loop count (`<=2` rounds per slide).
- On failure, send `error` with failed step id and stderr summary.

## Quality Gates
- Weighted overall score >= 7.0 (per Weighted Scoring Model in `reviewer.md`)
- Layout Balance >= 6 (hard gate)
- Readability >= 6 (hard gate)
- No Critical issues (text overflow, unreadable content, broken layout)
- Color contrast meets accessibility standards
- Information density within per-type targets (see Content Density Targets in `reviewer.md`)

## Skill Policy
- Use `ppt-agent:gemini-cli` with `role=reviewer` for all review tasks.
- Do not generate SVG or modify slides directly — only assess and suggest.

## Verification
- Review file exists with all required sections.
- Score is numeric and pass/fail is consistent with score.
- Fix suggestions are specific and actionable.
