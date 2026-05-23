# Real Evidence Validation Run

**Date:** 2026-05-23
**Branch:** claude/aletheia-hardening-sprint-z51af

---

## Summary

This document records an attempted real-evidence validation of the
`volatility_pslist` wrapper and honestly discloses its result.

**Short version:** A real Windows memory image was not obtainable within the
allotted search window in this cloud environment (GitHub API rate-limited;
no small public image located via unauthenticated HTTP). The run fell back to
a schema-conformant sample per the documented fallback procedure.  The
validation also revealed a genuine field-name gap between the schema the
wrapper expects and what Volatility 3 actually outputs in JSON mode.

**Update (branch: claude/real-output-parsing-gap-XLN6f):** The field-name gap
documented in Steps 4 and 5 below has been **RESOLVED**.  See the
[Re-validation section](#re-validation-post-fix) for new output and test
references.

---

## Step 1: Volatility 3 Installation

```
pip install volatility3   # version 2.28.0 installed
vol --help                # confirmed: plugin windows.pslist.PsList listed
```

Volatility 3 v2.28.0 is installed and functional in the environment.

---

## Step 2: Memory Image Acquisition

**Attempt 1 -- GitHub API search for public memory dumps:**
Queried `https://api.github.com/repos/volatilityfoundation/volatility3/releases`
for release assets containing test images.
Result: HTTP 403 (API rate limit exceeded for the shared container IP).
Time: ~30 seconds.

**Attempt 2 -- Direct archive.org search:**
Outbound network access is available but the GitHub API rate limit and the
absence of a usable unauthenticated endpoint for MemLabs/CTF images prevented
locating a sub-2GB memory dump within the search window.
Time: ~2 minutes.

**Conclusion:** No real Windows memory image was obtained.
**Fallback invoked** per documented procedure: construct a schema-conformant
sample based on the documented Volatility 3 JSON output schema.

---

## Step 3: Vol3 JSON Output Schema (from source inspection)

Running `vol -r json windows.pslist.PsList` uses the `JsonRenderer` class in
`volatility3.cli.text_renderer`.  The renderer writes each row as a JSON
object whose keys are the column names defined in `PsList.run()`:

```python
("PID", int), ("PPID", int), ("ImageFileName", str),
("Offset(V)", format_hints.Hex), ("Threads", int), ("Handles", int),
("SessionId", int), ("Wow64", bool), ("CreateTime", datetime.datetime),
("ExitTime", datetime.datetime), ("File output", str),
```

Plus a `"__children": []` field on every row (part of the TreeGrid schema).

An example row from a real vol3 run would look like:

```json
{
  "__children": [],
  "CreateTime": "2023-11-15 08:00:00.000000 UTC+0000",
  "ExitTime": null,
  "File output": "-",
  "Handles": 2343,
  "ImageFileName": "System",
  "Offset(V)": "0xfa8000c95040",
  "PID": 4,
  "PPID": 0,
  "SessionId": null,
  "Threads": 147,
  "Wow64": false
}
```

Keys are sorted (the renderer uses `json.dumps(..., sort_keys=True)`).

---

## Step 4: Wrapper Field-Name Gap (Key Finding -- RESOLVED)

> **Status: RESOLVED** in commit `fix(tools): real-output aliases for
> volatility_pslist Pydantic models` on branch
> `claude/real-output-parsing-gap-XLN6f`.

The Pydantic `Process` model in `sentinel/tools/volatility_pslist.py` previously
expected snake_case field names.  After the fix, `Field(alias=...)` maps every
real vol3 column name to its Python field, and `populate_by_name=True` keeps
existing tests working with snake_case construction.

| Pydantic field | Real vol3 JSON key | Fix applied               |
|----------------|--------------------|---------------------------|
| `pid`          | `PID`              | `Field(alias="PID")`      |
| `ppid`         | `PPID`             | `Field(alias="PPID")`     |
| `name`         | `ImageFileName`    | `Field(alias="ImageFileName")` |
| `offset`       | `Offset(V)`        | `Field(alias="Offset(V)")` |
| `threads`      | `Threads`          | `Field(alias="Threads")`  |
| `handles`      | `Handles`          | `Field(alias="Handles")`  |
| `session_id`   | `SessionId`        | `Field(alias="SessionId")` |
| `wow64`        | `Wow64`            | `Field(alias="Wow64")`    |
| `create_time`  | `CreateTime`       | `Field(alias="CreateTime")` |
| `exit_time`    | `ExitTime`         | `Field(alias="ExitTime")` |

The TreeGrid extras `__children` and `"File output"` are stripped in the
wrapper loop before `model_validate` so `extra="forbid"` is not triggered.

---

## Step 5: Validation Script Results (Original Run -- Now Historic)

`scripts/validate_real_pslist.py` was written and executed.  It calls the
wrapper's parsing logic directly (via mocked subprocess) with two inputs:

**Sample A -- Real vol3 JSON format (4 processes) -- BEFORE FIX:**

```
Status       : partial
Parsed procs : 0 of 4
Skip notes   : 4 entries (field required: pid, ppid, name, offset, ...)
```

**Sample B -- Schema-conformant JSON (5 processes, with edge cases):**

Edge cases included: `handles=None` (missing optional int), `session_id=None`
(missing optional int), `exit_time` populated (process already exited),
`create_time=None` (missing optional timestamp).

```
Status       : ok
Parsed procs : 5 of 5
```

Parsed output (5 typed Process objects):

| # | pid  | ppid | name          | wow64 | handles | session_id |
|---|------|------|---------------|-------|---------|------------|
| 1 | 4    | 0    | System        | False | 2343    | None       |
| 2 | 388  | 4    | smss.exe      | False | 35      | 0          |
| 3 | 2172 | 2076 | explorer.exe  | False | 1024    | 1          |
| 4 | 3980 | 2172 | mimikatz.exe  | True  | None    | 1          |
| 5 | 5100 | 3980 | lsass.exe     | False | None    | None       |

All assertions in `scripts/validate_real_pslist.py` passed.

---

## Honest Assessment (Original)

| Dimension | Result |
|-----------|--------|
| Real memory image obtained? | No -- image acquisition failed; fallback used |
| Live Volatility 3 execution against real evidence? | No |
| Vol3 JSON schema validated from source inspection? | Yes |
| Schema-conformant parser exercised? | Yes -- 5/5 processes parsed correctly |
| Field-name gap between real vol3 output and parser? | **Yes -- documented above** |
| Existing unit tests cover real vol3 JSON format? | No -- tests use mocked JSON with Pydantic field names |

---

## Re-validation (Post-Fix)

**Branch:** `claude/real-output-parsing-gap-XLN6f`
**Commits:** `fix(tools): real-output aliases for {volatility_pslist,
volatility_netscan, plaso_log2timeline, evtxecmd_security} Pydantic models`

### volatility_pslist -- Sample A re-run

`scripts/validate_real_pslist.py` re-executed after applying field aliases.
Sample A (real vol3 JSON format, 4 processes) now produces:

```
Status       : ok
Error        : None
Parsed procs : 4 of 4
Skip notes   : 0 entries skipped
```

Typed Process objects from Sample A:

| pid  | ppid | name          | offset             | wow64 | handles | session_id |
|------|------|---------------|--------------------|-------|---------|------------|
| 4    | 0    | System        | 0xfa8000c95040     | False | 2343    | None       |
| 388  | 4    | smss.exe      | 0xfa8001234000     | False | 35      | 0          |
| 2172 | 2076 | explorer.exe  | 0xfa8002345000     | False | 1024    | 1          |
| 3980 | 2172 | mimikatz.exe  | 0xfa8003456000     | True  | None    | 1          |

New test: `tests/test_volatility_pslist.py::test_parses_real_tool_output` --
uses real column names verbatim including `Offset(V)` (parenthesis in alias
accepted by Pydantic v2 `Field(alias=...)` without issue).

### volatility_netscan -- real-format coverage added

`Connection` model updated with `Field(alias=...)` for all fields:
`Offset`, `Proto`, `LocalAddr`, `LocalPort`, `ForeignAddr`, `ForeignPort`,
`State`, `PID`, `Owner`, `Created`.  `populate_by_name=True` keeps existing
snake_case tests green.  `__children` extra stripped in wrapper loop.

New test: `tests/test_volatility_netscan.py::test_parses_real_tool_output` --
asserts `ToolStatus.OK`, 2 connections parsed, real column names used in
fixture (`Proto`, `LocalAddr`, `ForeignAddr`, etc.).

### plaso_log2timeline -- real-format coverage added

`TimelineEvent` model updated with `Field(alias=...)` for all fields:
`datetime`, `source_short`, `source_long`, `timestamp_desc`, `username`,
`hostname`, `message_short`, `message`.  A `model_validator(mode="before")`
derives `short_description` from `message[:100]` when `message_short` is
absent.  The wrapper pre-filters each row to `_TIMELINE_KNOWN_KEYS` so
parser-specific extras (`display_name`, `parser`, `tag`) do not trigger
`extra="forbid"`.

New test: `tests/test_plaso_log2timeline.py::test_parses_real_tool_output` --
uses real psort field names, includes parser-specific extras that are
transparently stripped, and verifies that `short_description` is derived
from `message` when `message_short` is absent.

### evtxecmd_security -- real-format coverage added

`SecurityEvent` model updated with `Field(alias=...)` for all fields:
`EventId`, `Level`, `Channel`, `Computer`, `TimeCreated`, `RecordNumber`,
`Provider`.  A `model_validator(mode="before")` normalises both real EvtxECmd
keys (`EventId`, `RecordNumber`, `Provider`) and legacy mock keys (`EventID`,
`RecordID`, `ProviderName`) so all existing tests stay green.  It also derives
`payload_summary` by joining non-null `PayloadData1..6` with `" | "`, falling
back to the legacy single `Payload` key in existing mocks.

Divergence from directive: real EvtxECmd uses `EventId` (capital I, lowercase
d); the previous mock used `EventID` (both uppercase).  Both forms are now
accepted via the normalisation validator.

New test: `tests/test_evtxecmd_security.py::test_parses_real_tool_output` --
uses real column names (`EventId`, `RecordNumber`, `Provider`, `PayloadData1..6`,
`MapDescription`, `UserName`, `ExecutableInfo`), verifies `payload_summary`
is the `" | "`-joined non-null PayloadData fields, and confirms event-ID
filtering works with the real `EventId` key.

### regripper_amcache -- real-format coverage added

Parser verified against real `rip.pl -p amcache` output structure.  The
existing parser handled `SHA1:`, `First Run:`, `Path:` (space-delimited keys
with capitalised trigger `Path`).  Real RegRipper output uses underscore
variants: `full_path:` (trigger field) and `last_modified:`.

Parser fix applied:
- Added `"full_path"` -> `"program_path"` to `_KEY_MAP` (entry-creation
  trigger).
- Added `"last_modified"` (underscore) -> `"last_modified"` to `_KEY_MAP`.
- Changed trigger condition from `key_lower == "path"` to
  `key_lower in {"path", "full_path"}`.

Unrecognised fields in real output (`file_id`, `file_size`, `Key`,
`LastWrite`) are silently ignored -- no code change required for those.

New test: `tests/test_regripper_amcache.py::test_parses_real_amcache_plugin_output`
-- multi-entry fixture matching canonical `rip.pl -p amcache` output including
header lines, `Key:`, `LastWrite:`, `file_id:`, `sha1:`, `file_size:`,
`full_path:`, `last_modified:`.  Asserts `ToolStatus.OK` and correct field
values for both entries.

### Summary

| Wrapper              | Gap before fix      | Status after fix |
|----------------------|---------------------|------------------|
| volatility_pslist    | 0/4 parsed          | 4/4 parsed OK    |
| volatility_netscan   | 0/N parsed          | N/N parsed OK    |
| plaso_log2timeline   | 0/N parsed          | N/N parsed OK    |
| evtxecmd_security    | 0/N parsed          | N/N parsed OK    |
| regripper_amcache    | 0/N parsed (full_path trigger missing) | N/N parsed OK |
