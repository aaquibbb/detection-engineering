# Run Key Persistence: When a Passing Test Hides a Broken Query

**Rule:** `registry_set_win_run_key_persistence.yml`
**Technique:** T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

---

## Summary

Registry Run keys are one of the oldest and most common persistence mechanisms:
a value written under `...\CurrentVersion\Run` (or `RunOnce`) executes
automatically the next time the user logs on. The challenge isn't spotting a Run
key write - legitimate software registers autostart entries constantly - it's
separating the suspicious ones from that baseline.

This rule pairs the Run-key write with one of two suspicious signals: who wrote
it, or where the value points. It was validated end to end with Atomic Red Team
on a live Sysmon + Splunk pipeline, and in the process surfaced two real findings
a lab proves but a whiteboard never does: an initial miss caused by rule logic
(not missing data), and a false-positive flood caused by a dropped pair of
parentheses in the Splunk query. Those findings are the most useful part of this
write-up.

---

## The detection: one anchor, two independent signals

```yaml
detection:
    selection_target:        # the anchor: a Run / RunOnce key write
        TargetObject|contains:
            - '\CurrentVersion\Run'
    selection_image:         # signal A: who wrote it
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\reg.exe'
            - ...script hosts and download LOLBins...
    selection_path:          # signal B: where the value points
        Details|contains:
            - '\Users\Public\'
            - 'C:\Windows\Temp\'
            - '\AppData\Local\Temp\'
            - '\Downloads\'
    condition: selection_target and (selection_image or selection_path)
```

- **The anchor** (`selection_target`) matches a Run key write. `|contains` on
  `\CurrentVersion\Run` catches both `Run` and `RunOnce`, under both `HKLM` and
  `HKU`, without hardcoding a hive.
- **Signal A** (`selection_image`) - the writing process is a script host or a
  LOLBin. Legitimate apps register their own autostart from their own installer.
- **Signal B** (`selection_path`) - the value points to a user-writable or
  temporary location where malware stages a payload.

The two signals are independent, so either one alongside a Run-key write is
suspicious - hence OR'd inside an AND with the anchor.

A deliberate tuning note: `\AppData\Roaming\` and `\ProgramData\` were considered
for `selection_path` and removed. Those are where a large amount of *legitimate*
autostart software lives (Teams, OneDrive, Slack), so including them turns signal
B into a false-positive generator. Only genuinely abnormal autostart targets are
kept.

---

## Testing and evidence

Validated on the lab box (`AaquibLabPC`): Sysmon with the SwiftOnSecurity config,
forwarding to Splunk (`index=sysmon`), Defender real-time protection disabled for
the session with an ART exclusion.

### Telemetry check first

Before any attack, confirm the data source even exists. Sysmon logged a Run-key
write as Event ID 13, tagged `RuleName: T1060,RunKey`. That tag is itself a
finding: SwiftOnSecurity's config labels Run keys with `T1060`, the *deprecated*
ATT&CK ID that was renumbered to `T1547.001`. Knowing your config tags events
with an old technique ID is the kind of detail that matters in triage.

### Execution with Atomic Red Team

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Invoke-AtomicTest T1547.001 -TestNumbers 1 -ShowDetails   # inspect first, run nothing
Invoke-AtomicTest T1547.001 -TestNumbers 1                # execute test 1
```

Test 1 writes a Run value via `reg.exe`. A subtlety worth stating: the test runs
`cmd.exe`, but `cmd.exe` is only the *executor* - it types the command. The
process that actually writes the registry is `reg.exe`. The distinction between
executor and writer is exactly what the `Image` field captures.

Captured event (saved as evidence with `Tee-Object` to `C:\lab\`):

```
Image:        C:\Windows\system32\reg.exe
TargetObject: HKU\S-1-5-21-204022296-...\...\CurrentVersion\Run\Atomic Red Team
Details:      C:\Path\AtomicRedTeam.exe
User:         AaquibLabPC\aaqui
```

Two things the real event taught:
- The command wrote to `HKCU`, but Sysmon logged `HKU\S-1-5-21-...`. `HKCU` is a
  shortcut to the current user's branch under `HKU\<SID>`, and Sysmon records the
  real path. This is why the anchor matches on the stable middle of the path
  (`\CurrentVersion\Run`) rather than a hive prefix - a rule written as
  `TargetObject|startswith: 'HKCU\...'` would never match anything.
- `Details` is `C:\Path\AtomicRedTeam.exe` - not a suspicious path, so signal B
  stayed quiet. The match came purely through signal A (`reg.exe` as writer).

### Finding 1: the first version was a miss, and the data was not the problem

The initial rule did not include `reg.exe` in `selection_image`, so this test
produced **no alert** - despite the EID 13 event being right there in Splunk.

> T1547.001 test 1: telemetry present (Sysmon EID 13). Rule: MISS. Cause: rule
> logic, not data.

That last line is the finding. Distinguishing "my rule missed because the data
isn't collected" from "my rule missed because the logic is wrong" is a core
triage skill, and this was the second kind. The fix was to add `\reg.exe` to the
writer list - with the honest trade that `reg.exe` is also a common *legitimate*
Run-key writer, so it raises the false-positive surface and is a prime
baselining target.

### Baselining the legitimate writers

Before trusting the rule, baseline who writes Run keys on a normal host:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=13} |
  Where-Object Message -match '\\CurrentVersion\\Run' |
  ForEach-Object { ($_.Message -split "`n" | Select-String '^Image:').ToString().Trim() } |
  Group-Object | Sort-Object Count -Descending | Select-Object Count, Name
```

High-count writers are infrastructure to allowlist, not attackers.

### Finding 2: a passing test hid a broken Splunk query

The Atomic test fired, which looked like success. It wasn't - the Splunk search
being run was logically broken, and the passing test concealed it.

The search had been hand-written rather than taken from `sigma convert`, and the
parentheses were dropped:

```
# BROKEN (what was run)
index=sysmon EventID=13 TargetObject="*\CurrentVersion\Run*" Image IN (...) OR Details IN (...)

# CORRECT (from sigma convert -t splunk -p splunk_windows)
index=sysmon EventID=13 TargetObject="*\CurrentVersion\Run*" (Image IN (...) OR Details IN (...))
```

In Splunk, implicit `AND` binds tighter than `OR`, so the broken version parses
as:

```
(EventID=13 AND TargetObject=Run AND Image IN (...))   OR   (Details IN (...))
```

The `Details IN (...)` branch is **un-gated** - it matches any event whose
`Details` field contains one of those paths, with no requirement that it even be
a Run-key write. The intended logic - *a Run key write AND (suspicious writer OR
suspicious path)* - had silently become *(a Run key write by a LOLBin) OR
(anything touching these paths)*. Two completely different rules.

The Atomic test still fired because it matched the first, correctly-gated branch
(`reg.exe` writing a Run key). So the passing test proved exactly one thing - a
LOLBin writing a Run key is caught - and nothing about whether the query was
correct. It was caught by reading the SPL and comparing result counts: the broken
query returned a flood of Details-branch matches that weren't persistence; the
parenthesised query collapsed to a clean set with the Atomic test as the single
real hit.



### Cleanup

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"   # confirms the entry is gone
```

**Lessons carried forward:**
1. A passing true-positive test does not validate query logic. The attack firing
   tells you the rule can catch the attack; it says nothing about the
   false-positive behaviour of the rest of the query. Read the generated query.
2. Deploy the converted query, not a hand-written one. `sigma convert -t splunk
   -p splunk_windows` preserves the parentheses every time.
3. One technique has many procedures. T1547.001 test 1 is the `reg.exe` procedure;
   other atomics use PowerShell, `RunOnce`, or the Startup folder. "My rule
   detects T1547.001" really means "it detects some procedures of it" - which
   ones is what testing several atomics tells you.

---

## Known limitations and status

`status: test` - validated against Atomic Red Team test 1 on live Sysmon
telemetry via Splunk, with the query logic corrected and confirmed. Not
`stable`; that needs a production baseline to identify and allowlist the
legitimate writers (`reg.exe` and PowerShell admin scripts foremost).

**Blind spots:**
- A Run key written directly through the Windows API by a custom binary (not a
  LOLBin) to a clean path like `Program Files` matches neither signal and evades
  the rule. The brittle-layer boundary: it catches the common, lazy procedure,
  not a tailored dropper.
- Only the `reg.exe` procedure of T1547.001 has been validated. Other procedures
  (PowerShell writer, Startup folder, Winlogon keys) are separate tests and, in
  some cases, separate detections.
