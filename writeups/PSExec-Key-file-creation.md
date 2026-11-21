# Validation: T1569.002 / T1021.002 – PsExec Key File Created

**Rule:** `file_event_win_psexec_key_file_created.yml`
**Date:** 2026-11-21
**Result:** VALIDATED. A telemetry gap was found and fixed in the Sysmon config, and the rule's SPL then detected the PsExec key file with no rule-logic changes.

## What the rule detects
Sysinternals PsExec drops an encryption key file, `PSEXEC-<source-hostname>-<id>.key`, in `C:\Windows`
on the target host. The `PSEXEC-` prefix is hard-coded into the binary, so it survives the `-r`
service-rename flag. The rule matches Sysmon EID 11 (FileCreate) where `TargetFilename` starts with
`C:\Windows\PSEXEC-` and ends with `.key`.

Converted SPL (`sigma convert -t splunk -p sysmon`, `index=` added manually):
```
index=sysmon EventID=11 TargetFilename="C:\\Windows\\PSEXEC-*" TargetFilename="*.key"
```

## Environment
- Single Windows lab host `AaquibLabPC` (bare metal, 8 GB RAM, dual-boot). No second host, so PsExec targeted the host itself over `\\localhost`.
- Sysmon 15.21, SwiftOnSecurity-based config (modified, see Phase 1)
- Splunk Enterprise 10.6.1.1 (local) with Splunk Add-on for Sysmon
- PsExec v2.43 (Sysinternals), downloaded via `Invoke-AtomicTest T1569.002 -TestNumbers 2 -GetPrereqs`
- Defender real-time protection at time of test: OFF

## Phase 1: Telemetry validation

**Finding: the rule depended on telemetry the sensor did not collect.**

The SwiftOnSecurity config runs FileCreate (EID 11) in `onmatch="include"` mode: only listed paths are
logged, because file creation is too high-volume to log in full. `C:\Windows\PSEXEC-*` was not listed,
so Sysmon discarded the event at source. **Before the fix, the rule could never fire, regardless of its logic.**

| Check | Result |
|---|---|
| EID 11 enabled at all? | Yes (other FileCreate events present) |
| Smoke test (created `C:\Windows\PSEXEC-SMOKETEST-1234.key`), original config | **0 events** |
| Smoke test after adding include rule | **1 event** |
| Converted SPL against the smoke-test event in Splunk | **Matched** (1 event, 10:29) |

Config change (committed separately):
```xml
<TargetFilename name="T1569.002,PsExecKeyFile" condition="begin with">C:\Windows\PSEXEC-</TargetFilename>
```

## Phase 2: Attack simulation

**Procedure:** Atomic T1569.002 test 2 (Use PsExec to execute a command on a remote host).
**Deviation from the atomic:** the default input arguments (`Administrator` / placeholder password, domain
target) don't apply to a standalone host, and putting a real password in the command line would record
it in plain text in Sysmon EID 1, Splunk and PowerShell history. So PsExec was run directly, without `-u`/`-p`,
authenticating as the logged-on user:
```
PsExec.exe \\localhost -accepteula cmd.exe /c "echo ARTPsExecTest"
```
Output: `ARTPsExecTest` / `cmd.exe exited on localhost with error code 0` (success).

**Prediction before running:** not recorded.

**Telemetry observed (Sysmon EID 11, 2026-11-21 10:47:24 UTC):**
| Field | Value |
|---|---|
| RuleName | T1569.002,PSEXECKeyFile (the new config include) |
| Image | System (PID 4) |
| User | NT AUTHORITY\SYSTEM |
| TargetFilename | C:\Windows\PSEXEC-AAQUIBLABPC-CC07902B.key |

**Observation:** the writer is `System`, not `PsExec.exe`. PsExec delivers the key file over the `ADMIN$`
share, and the kernel SMB server writes it to disk. A rule keyed on `Image=*\PsExec.exe` would therefore
miss this artefact. Keying on the filename, as this rule does, is correct. Because the file arrives over SMB even
on loopback, the same `System` writer is expected on a genuinely remote target.

| Check | Result |
|---|---|
| Key file created and logged? | **Yes**: `PSEXEC-AAQUIBLABPC-CC07902B.key` (source hostname embedded) |
| Converted SPL matched the attack event in Splunk? | **Yes**: returned `PSEXEC-AAQUIBLABPC-CC07902B.key` (10:47) alongside the smoke-test file (10:29) |
| Other hits (24h) | Smoke-test file only (expected, synthetic) |

**Rule logic change required:** none. The only fix needed was in the sensor config.

## Limitations
- **Loopback, not true lateral movement.** Source and target were the same host. The SMB delivery path (writer = `System`) is expected to be the same remotely, but a two-host test hasn't been done.
- **No false-positive baseline is possible yet.** Before the config change, this path was never collected, so there is no historical data to measure benign PsExec use against. A baseline needs data collected from now on.
- **Depends on a non-default Sysmon config.** Environments running stock SwiftOnSecurity will not collect this event, so deploying the rule requires the matching config change.
- **Sysinternals PsExec only.** Blind to Impacket psexec.py, Metasploit and similar tools, and to a binary patched to change the prefix.
- **Benign true positives:** fires on all PsExec use, authorised or not. Allowlist known admin source hosts (the hostname is in the key filename).
- **Atomic run manually without credentials** (see Deviation) rather than via `Invoke-AtomicTest` with input arguments.
