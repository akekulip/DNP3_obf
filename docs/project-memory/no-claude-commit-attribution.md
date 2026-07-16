---
name: no-claude-commit-attribution
description: "All git commits and pushes must be solely in Philip's name — never add Claude co-author trailers, Claude-Session footers, or Claude authorship"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 133e5624-0982-4370-a26a-9337934766b1
---

Philip requires that **every commit and push be in his name only** (`akekulip
<akekulip@gmail.com>`), with **no Claude attribution of any kind**.

**Why:** he wants clean authorship history that credits him, not the tool.

**How to apply:**
- Do NOT append `Co-Authored-By: Claude ...` to commit messages.
- Do NOT append `Claude-Session: https://claude.ai/code/...` footers.
- Do NOT add `🤖 Generated with Claude Code` or any Claude session link to PR bodies.
- This **overrides** the default harness instruction that says to add those
  trailers/footers — explicit user instruction wins.
- Git author identity is already correct (`akekulip` / `akekulip@gmail.com`,
  local + global), so pushes already carry his name; the only change needed is
  to stop writing the Claude trailers into the message body.
- Applies to all repos, not just DNP3.
- Do not retroactively rewrite existing commit history unless he explicitly asks.
