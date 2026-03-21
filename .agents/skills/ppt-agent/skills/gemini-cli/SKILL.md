---
name: gemini-cli
description: |
  [Trigger] When PPT workflow needs SVG slide quality review via Gemini.
  [Output] Structured review assessment with scores, pass/fail, and fix suggestions.
  [Skip] For content authoring or SVG generation tasks (those are handled by Claude).
  [Ask] No user input needed; invoked by review-core agent.
  [Resource Usage] Use references/, scripts/ (`scripts/invoke-gemini-ppt.ts`).
allowed-tools:
  - Bash
  - Read
  - Write
arguments:
  - name: role
    type: string
    required: true
    description: "reviewer"
  - name: prompt
    type: string
    required: true
    description: "Final prompt passed to Gemini"
  - name: image
    type: string
    required: false
    description: "Image path for vision tasks (rendered SVG screenshots)"
---

# Gemini CLI - PPT Slide Reviewer

SVG slide quality reviewer via `scripts/invoke-gemini-ppt.ts`. Evaluates layout, visual hierarchy, color harmony, typography, and readability. The script automatically tries fallback models if the primary model is unavailable.

## Script Entry

```bash
npx tsx scripts/invoke-gemini-ppt.ts \
  --role "<role>" \
  --prompt "<prompt>" \
  [--image "<path>"] \
  [--model "<model>"] \
  [--output "<path>"]
```

## Resource Usage

- Role prompts: `references/roles/{role}.md`
- Execution script: `scripts/invoke-gemini-ppt.ts`

## Roles

| Role     | Purpose                        | CLI Flag          |
| -------- | ------------------------------ | ----------------- |
| reviewer | SVG slide quality review       | `--role reviewer` |

## Workflow

### Step 1: Read the SVG source and style tokens

Before calling Gemini, read the SVG file content and the relevant style YAML so you can include them in the prompt. The reviewer needs the actual SVG source code to inspect element attributes (font-size, fill, opacity, coordinates).

### Step 2: Build the review prompt

Construct a prompt that includes:
- The full SVG source code (or relevant excerpts for very large files)
- The style token values (colors, fonts, border-radius, gap)
- The slide context (index, topic, presentation style name)

### Step 3: Call Gemini

```bash
npx tsx scripts/invoke-gemini-ppt.ts \
  --role reviewer \
  --prompt "$REVIEW_PROMPT" \
  --output "${RUN_DIR}/reviews/gemini-raw-${SLIDE_INDEX}.md"
```

The script tries models in order: default → gemini-2.5-pro → gemini-2.5-flash. If all fail, it exits with code 2.

### Step 4: Handle the result

- **Exit code 0**: Gemini responded. Read the output file and extract the structured review.
- **Exit code 2**: All Gemini models unavailable. **Fall back to Claude self-review** using the same quality standards from `references/roles/reviewer.md`. This is the expected degradation path — the review must still happen, just without the cross-model perspective.
- **Exit code 1**: Script error (bad args, missing file). Fix and retry.

### Step 5: Write the final review

Whether from Gemini or Claude fallback, write the structured review to `${run_dir}/reviews/review-{nn}.md` using the output format defined in `references/roles/reviewer.md`.

---

## Prompt Templates

### Role: reviewer — SVG Quality Review

```bash
npx tsx scripts/invoke-gemini-ppt.ts \
  --role reviewer \
  --output "${RUN_DIR}/reviews/gemini-raw-${N}.md" \
  --prompt "
## Task
Review the SVG presentation slide for design quality.

## Slide Content
${SVG_CONTENT}

## Style Reference
${STYLE_NAME} style with tokens: ${STYLE_TOKENS}

## Review Criteria
1. Layout Balance: card arrangement, visual weight distribution, whitespace usage
2. Color Harmony: palette consistency, contrast ratios, accent usage
3. Typography: hierarchy clarity, font size appropriateness, line spacing
4. Readability: text legibility at presentation resolution, information flow
5. Information Density: content-to-whitespace ratio, cognitive load

## Output Format
Structured review with:
- overall_score: 1-10
- pass: true/false (pass if >= 7)
- per-criterion scores and notes
- issues: list of specific problems with severity (critical/major/minor)
- fixes: actionable suggestions for each issue with specific values
"
```

---

## Fallback Strategy

The dual-model approach (Claude generates, Gemini reviews) provides value through independent perspective. When Gemini is unavailable, the review-core agent should:

1. Read `references/roles/reviewer.md` for quality standards and methodology.
2. Apply the same structured review process: 5 criteria, numeric scores, pass/fail gate, issue severity, actionable fixes.
3. Mark the review as "Claude self-review" in the output header so downstream consumers know it was not cross-model validated.

The review quality standards (14px min font, 20px min gap, WCAG AA contrast, 7±2 info units) are the same regardless of which model performs the review.

---

## Constraints

| Required                                  | Forbidden                               |
| ----------------------------------------- | --------------------------------------- |
| MUST attempt Gemini via script first      | Skip Gemini without trying              |
| MUST fall back to self-review on exit 2   | Fail the entire review if Gemini is down|
| MUST use reviewer role quality standards  | Send generic/empty prompts to Gemini    |
| MUST persist output to run_dir artifacts  | Discard Gemini output                   |
| Review MUST produce structured scores     | Return vague qualitative-only feedback  |
| MUST include SVG source in the prompt     | Review based on filename alone          |

## Collaboration

1. **review-core** agent invokes `reviewer` role for SVG quality assessment
2. Review output feeds back to **slide-core** for fix iterations
