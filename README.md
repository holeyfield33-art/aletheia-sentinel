# Aletheia Sentinel

> Autonomous incident response on the SANS SIFT Workstation, with spectral
> self-correction to catch agent hallucinations before they reach the case file.

**Hackathon:** [FIND EVIL!](https://findevil.devpost.com/) — SANS, Apr–Jun 2026
**License:** Apache 2.0
**Status:** Sprint in progress

## Why this exists

An AI-powered adversary can go from initial access to full domain control in
under eight minutes. Human responders are still pulling up their toolkit.
Sentinel closes that gap with a multi-agent system that runs on top of the
SIFT Workstation's 200+ forensic tools, exposed through a typed Model
Context Protocol surface, with every tool call cryptographically receipted
and every finding gated by a statistical hallucination check.

## What makes this different

Most submissions to this hackathon will be Claude Code wrappers with better
prompts. Sentinel is built on three structural ideas instead:

1. **A typed MCP server, not a shell.** The agent calls
   `extract_mft_timeline(image=...)`, not `bash("mft2csv ...")`. Destructive
   commands are not in the tool surface, so the agent physically cannot run
   them. Architectural enforcement, not prompt enforcement.
2. **A hash-linked HMAC receipt chain.** Every tool execution writes a
   receipt that points at the previous receipt's digest. Tampering breaks the
   chain. Judges can trace any finding back to the exact subprocess call that
   produced it.
3. **A spectral self-correction loop.** Reasoning samples are scored by the
   [Geometric Brain](https://geometric-brain-mcp.onrender.com) MCP, which
   measures GUE eigenvalue spacing as a proxy for reasoning coherence. When
   the agent's reasoning drifts from a healthy manifold, the finding is
   rejected and re-investigated. This is the differentiator.

## Architecture at a glance

```
Scout → MCP Server → SIFT tool → ToolResult
              ↓
        Receipt Chain (HMAC, hash-linked)
              ↓
        Nitpicker → Spectral Gate
              ↓
       (accept or re-investigate)
              ↓
        Judge → Signed Report
```

Full diagram and trust-boundary table in [`docs/architecture.md`](docs/architecture.md).

## Quickstart

```bash
# In GitHub Codespaces (devcontainer config included)
pip install -e '.[dev]'

export ALETHEIA_RECEIPT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"

pytest
```

## Sprint roadmap

| Week | Milestone |
|------|-----------|
| 1 | MCP server skeleton, audit chain, orchestrator core ← **you are here** |
| 2 | Wrap 12–20 SIFT tools as typed functions; Scout/Nitpicker/Judge LLM bindings |
| 3 | Spectral gate wired to geometric-brain-mcp; accuracy benchmark harness |
| 4 | Demo video, accuracy report, submission polish |

## Repo layout

```
src/sentinel/
  audit/        HMAC receipt chain
  tools/        typed SIFT tool wrappers (Pydantic)
  agents/       Scout, Nitpicker, Judge, Orchestrator
  spectral/     Geometric Brain gate
  benchmark/    accuracy harness
docs/
  architecture.md
tests/
```

## Built on prior Aletheia work

- [`aletheia-cyber-core`](https://pypi.org/project/aletheia-cyber-core/) —
  tri-agent pipeline, HMAC audit receipts, Ed25519 policy manifests
- [`mneme`](#) — FastMCP server patterns, typed tool surfaces
- [`geometric-brain-mcp`](https://geometric-brain-mcp.onrender.com) —
  GUE spacing health checks

## License

Apache 2.0. See [`LICENSE`](LICENSE).
