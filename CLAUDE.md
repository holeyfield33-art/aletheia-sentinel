# Aletheia Sentinel - Developer Guide for Claude

## Project overview

Autonomous incident response on the SANS SIFT Workstation. Three structural
differentiators: typed MCP tool surface (no shell), HMAC hash-linked receipt
chain, and spectral self-correction via Geometric Brain eigenvalue spacing.

## Code quality requirements

All three checks must pass before any commit:

```bash
ruff check src tests   # All checks passed!
mypy                   # Success: no issues found
pytest                 # at least 18 tests, all green
```

## Strict typing rules

- All functions and methods must have complete type annotations (params + return).
- No bare `Any` in non-test code unless truly unavoidable and commented.
- `from __future__ import annotations` at the top of every module.
- No implicit optional (`x: str = None` is wrong; use `x: str | None = None`).
- Pydantic models: `model_config = ConfigDict(frozen=True, extra="forbid")` by default.

## Error handling rules

- No broad `except Exception` or `except:` clauses. Catch only the specific
  exception type you can meaningfully handle.
- Let unexpected errors propagate; the orchestrator caps are the safety net.
- `ChainIntegrityError` must be raised (never swallowed) when receipt validation fails.

## ASCII-only source files

All `.py` files must contain only ASCII characters. No Unicode identifiers,
no non-ASCII string literals, no curly quotes. CI will catch violations via ruff.

## Git discipline

- Do NOT run destructive git commands (reset --hard, push --force, branch -D,
  checkout -- ., clean -f) without explicit user confirmation.
- Do NOT commit forensic evidence files (*.raw, *.E01, *.dd, *.vmem, *.aff4).
  The .gitignore enforces this but be vigilant.
- Do NOT commit secrets or .env files.
- Prefer `git push -u origin <branch>` for first push of a branch.

## Architecture invariants

- The MCP server exposes NO shell execution surface. Every tool is a typed
  Python function. Destructive commands do not exist in the tool surface.
- Receipts store ONLY SHA-256 digests of input/output, never raw bytes.
- The receipt chain is append-only and single-threaded per session.
- `ReceiptChain.verify()` must be called before producing any final report.
- Spectral gate: HEALTHY r >= 0.55, CAUTION r >= 0.40, STRESSED otherwise.
  STRESSED findings are rejected and re-investigated, never accepted.

## Adding new SIFT tool wrappers (Week 2+)

1. Create `src/sentinel/tools/<tool_group>.py`.
2. Define a frozen Pydantic payload model (e.g. `PslistPayload`).
3. Implement the async tool function returning `ToolResult`.
4. Register with the MCP server in `src/sentinel/mcp_server.py`.
5. Add at least one happy-path and one error-path test.
6. Run the full quality bar before committing.

## Environment variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `ALETHEIA_RECEIPT_SECRET` | Yes (prod) | HMAC key for receipt chain signing |

Generate a secret: `python -c "import secrets; print(secrets.token_hex(32))"`
