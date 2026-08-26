# Field Selection: Detecting on What the Adversary Can't Cheaply Change

**Rule:** `proc_creation_win_powershell_encoded_command.yml`  
**Technique:** T1059.001, T1027

---

## Summary

A detection is only as durable as the fields it depends on. Some fields an adversary can change in seconds; others cost them real effort. This write-up explains why the encoded-PowerShell rule in this repo keys on `OriginalFileName` and `CommandLine` instead of `Image` and `ParentImage`, and sets out the rule I use for choosing fields.

The short version: **don't ask where a field comes from, ask what it costs to change it.**

---

## 1. Why "kernel vs caller" is the wrong test

A natural first instinct is to split fields into two groups: values supplied by the caller (don't trust) and values derived by the kernel or read from disk (do trust).

That test breaks on `ParentImage`.

`ParentImage` really is derived from the actual parent process. Sysmon is not being handed a value by the attacker. But PPID spoofing defeats it anyway: the attacker passes `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to `CreateProcess`, and Windows genuinely creates the process under whatever parent they picked. The kernel then reports that parent accurately. Nothing lied to the kernel — the lie happened one layer up.

`Image` breaks the test from the other side. It's read from disk rather than supplied by the caller, but copying `powershell.exe` to `C:\Users\Public\svchost.exe` costs nothing at all.

So a field can be kernel-sourced and still fully under adversary control. Provenance isn't the useful axis.

---

## 2. The useful axis: tamper cost

| Cost to change | Fields | Why |
|---|---|---|
| **Free** | `Image` filename, `ParentImage`, `CommandLine` | Renaming a binary, spoofing a parent PID, and obfuscating arguments are all trivial and widely tooled. |
| **Cheap** | `Hashes`, `CurrentDirectory` | Recompiling or altering a single byte produces a new hash. |
| **Expensive** | `OriginalFileName`, `SignatureStatus` | `OriginalFileName` comes from the PE version metadata. Editing it modifies the binary, which invalidates the Authenticode signature — so the attacker either gives up a valid signature or gives up the rename. |
| **Very expensive or impossible** | `IntegrityLevel`, `ProcessGuid`, `LogonId` | Assigned by the kernel or by Sysmon itself. Faking `IntegrityLevel` would require the privilege escalation you're trying to detect. `ProcessGuid` has no attacker-facing surface at all. |

The practical consequence: **every `and` in a rule that relies on a free field is a separate place the rule breaks.** Three cheap conditions means three independent ways to evade it. This is why "add more conditions to cut false positives" is the wrong reflex — the quiet is bought with blindness.

---

## 3. When a cheap field is still the right choice

Taken literally, "never detect on attacker-controlled fields" would delete most of detection engineering. `CommandLine` is free to manipulate, and it's also where intent lives.

The way through is to separate **what the adversary can vary** from **what the adversary must do**.

To run an encoded command, they have to pass an encoded command. They can change the abbreviation (`-e`, `-ec`, `-enc`, `-EncodedCommand`), add whitespace, or build the string from variables — but the base64 payload has to reach the interpreter. The field is controllable; the requirement isn't.

Same reasoning applies to `GrantedAccess: 0x1010` for LSASS credential access. The tool can be renamed, recompiled, and packed, but reading LSASS memory requires requesting a handle with those rights. That's a choke point, not a string.

**So: prefer expensive fields where they exist. Where you have to use a cheap field, key on the part their objective forces them to include.**

---

## 4. Before and after

### Before

```yaml
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains: '-enc'
        ParentImage|endswith: '\cmd.exe'
    condition: selection
```

Three conditions, three ways out:

1. **`Image`** — rename the binary. Free.
2. **`CommandLine|contains: '-enc'`** — PowerShell accepts any unambiguous prefix, so `-e <base64>` runs identically and doesn't match. Free.
3. **`ParentImage`** — the most damaging of the three. Beyond PPID spoofing, the attacker can simply not use `cmd.exe`. A Word macro calling `Shell()` gives `WINWORD.EXE` as the direct parent. A `.vbs` dropper gives `wscript.exe`. WMI execution gives `wmiprvse.exe`. A scheduled task gives `svchost.exe`.

Worth stating plainly: **this version would not have caught the intrusion chain it was written from**, had the macro launched PowerShell directly instead of going through a shell first.

### After

```yaml
detection:
    selection_binary:
        OriginalFileName:
            - 'PowerShell.EXE'
            - 'pwsh.dll'
    selection_encoded:
        CommandLine|re: '\s-[eE][ncodedmalsCP]*\s+[A-Za-z0-9+/=]{15,}'
    condition: all of selection_*
```

**`Image` → `OriginalFileName`.** A renamed or relocated binary still matches, because PE metadata survives a file copy. `pwsh.dll` is included because PowerShell 7 reports the DLL name rather than the executable — a detail that only surfaces through testing.

**Match the payload, not the flag.** The regex requires an abbreviated `-e*` parameter *followed by at least 15 base64 characters*. A plain `-e` substring would fire on `-ExecutionPolicy` and `-ErrorAction`, two of the most common parameters in legitimate PowerShell, and would be unusable at scale. The signal is a parameter carrying a payload.

**Parent dropped from the gate.** Encoded PowerShell with a long base64 payload is worth looking at regardless of what launched it. Some precision is traded for coverage. Parent process is more useful for weighting severity — escalate when it's an Office application, a script host, or a WMI provider — than as a hard condition that's easy to route around.

---

## 5. Known limitations

This rule is `status: experimental`. It has not been baselined against production volume, and it should not be shipped as an alert until it has been.

The expected dominant false positive is software deployment tooling. SCCM, Intune, and PDQ packages routinely wrap PowerShell in batch files and use `-EncodedCommand` specifically to avoid quote-escaping problems in batch. In a large estate this is high-volume and entirely legitimate. Backup and monitoring agents running pre- and post-job scripts are a secondary source, as are legacy batch-wrapped scheduled tasks and GPO logon scripts.

The baseline to run before shipping, over a 30-day window:

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"\s-[eE][ncodedmalsCP]*\s+[A-Za-z0-9+/=]{15,}"
| summarize Hosts=dcount(DeviceName), Hits=count()
    by InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Hits desc
```

High volume across a high number of hosts indicates infrastructure, not an adversary. Those results become the allowlist. What the tail looks like after tuning determines whether this ships as an alert or stays a scheduled hunt.

One further trade-off: regex is not handled efficiently by every SIEM backend. An enumerated list of anchored variants (`' -e '`, `' -ec '`, `' -enc '`, and so on) converts cleanly everywhere and reads more easily, at the cost of eventually missing a variant nobody thought of. The regex is the better choice here, but the alternative is worth knowing.
