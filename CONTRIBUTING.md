# Contributing to Aletheia Sentinel

## Dev environment setup

```bash
git clone https://github.com/holeyfield33-art/aletheia-sentinel.git
cd aletheia-sentinel
pip install -e '.[dev]'

# Required for run/verify subcommands (not needed for demo or tests)
export ALETHEIA_RECEIPT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

## Running the test suite

All three checks must pass before any commit:

```bash
python -m pytest                     # 153 tests, all green
python -m mypy                       # Success: no issues found
python -m ruff check src tests       # All checks passed!
```

Run the demo to confirm end-to-end behaviour (no API key required):

```bash
sentinel demo
```

## Adding a new SIFT tool wrapper

Six existing wrappers are templates:
`src/sentinel/tools/volatility_pslist.py`,
`volatility_netscan.py`, `volatility_cmdline.py`, `regripper_amcache.py`,
`plaso_log2timeline.py`, `evtxecmd_security.py`.

Steps:

1. Create `src/sentinel/tools/<tool_group>.py`.
2. Define a frozen Pydantic payload model (e.g. `PslistPayload`).
3. Implement the async tool function returning `ToolResult`.
4. Register it in `src/sentinel/mcp_server.py`.
5. Add at least one happy-path test and one error-path test.
6. Run all three quality checks before committing.

## Code style rules

Pulled directly from `CLAUDE.md`:

- `from __future__ import annotations` at the top of every `.py` file.
- All functions and methods: complete type annotations on params and return.
- No implicit optional: use `x: str | None = None`, not `x: str = None`.
- Pydantic models: `model_config = ConfigDict(frozen=True, extra="forbid")`.
- No broad `except Exception` or bare `except`. Catch only the specific type
  you can meaningfully handle.
- ASCII-only source files. No Unicode identifiers, no non-ASCII literals.
- No bare `Any` in non-test code unless truly unavoidable and commented.

## Opening a PR

1. Branch from `main`: `git checkout -b feat/my-feature`.
2. Write the code + tests. All three quality checks must be green.
3. Commit with a descriptive message (`feat(tools): add strings wrapper`).
4. Push and open a PR against `main`.
5. PR description should explain the *why*, not just the *what*.
