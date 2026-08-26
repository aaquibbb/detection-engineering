# Choosing What to Detect On 

**Rule:** `EncodedPowerShell.yml`  
**Technique:** T1059.001, T1027

---

## Summary

Detection logic is only as durable as the fields it depends on. This write-up documents why the encoded-PowerShell rule in this repo keys on `OriginalFileName` and `CommandLine` rather than `Image` and `ParentImage`, and sets out the general framework I use to decide which fields are worth building on: **not where the field comes from, but what it costs an adversary to change it.**

---

## 1. The naive framing, and why it fails

A common first instinct is to divide telemetry fields into two buckets:

- fields supplied by the caller (untrustworthy)
- fields derived by the kernel or read from disk (trustworthy)

The instinct is directionally right as some fields are more dependable than others, but the dividing line is wrong, and relying on it produces false confidence.

**`ParentImage` is the counterexample.** It is genuinely derived from the real parent process. Sysmon is not being fed a value by the caller. Yet PPID spoofing defeats it completely: an adversary passes `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to `CreateProcess`, and Windows honestly creates the process under a parent of the attacker's choosing. The kernel then faithfully reports a lie told one layer upstream.

`Image` fails the same test from the other direction. It is read from disk, not supplied by the caller, but copying `powershell.exe` to `C:\Users\Public\svchost.exe` costs an adversary nothing.

So a field can be kernel-sourced and adversary-controlled at the same time. Provenance is not the right axis.

---

## 2. The framing that holds: tamper cost

The useful question is: **what does it cost the adversary to change this value?**

| Cost | Fields | Why |
|---|---|---|
| **Free** | `CommandLine`, `Image` filename, `ParentImage` | Obfuscation, renaming, and PPID spoofing are all trivial and well-tooled. `CommandLine` is additionally writable in the PEB after process creation. |
| **Cheap** | `Hashes`, `CurrentDirectory` | Recompile or flip a byte and the hash changes. |
| **Expensive** | `OriginalFileName`, `SignatureStatus` | Changing PE metadata requires modifying the binary, which invalidates its Authenticode signature. The adversary must now either source a signed binary that is no longer validly signed, or accept exposure to signature-status detections. |
| **Very expensive / not possible** | `IntegrityLevel`, `ProcessGuid`, `LogonId` | Kernel- or agent-assigned. Forging `IntegrityLevel` presupposes the escalation you are trying to detect. `ProcessGuid` has no adversary-facing surface at all. |

Every `and` in a rule that depends on a *free* field is an independent place the detection breaks. This is the brittleness cost of adding conditions, and it is why "add more conditions to reduce false positives" is the wrong default instinct — you are buying quiet with blindness.

---

## 3. The exception: functional constraint

Taken literally, "never detect on adversary-controlled fields" would delete most of detection engineering. `CommandLine` is free to manipulate, and it is also where intent lives.

The resolution is to distinguish **freedom of expression** from **freedom of action**.

To execute an encoded command, an adversary *must* pass an encoded command. They can vary the parameter abbreviation (`-e`, `-ec`, `-enc`, `-EncodedCommand`), pad whitespace, or split the payload across variables — but the base64 blob has to arrive at the interpreter. The field is controllable; the requirement is not.

The same logic explains why `GrantedAccess: 0x1010` is a high-fidelity signal for LSASS credential access. The tool can be renamed, recompiled, and obfuscated, but obtaining a handle to LSASS memory requires requesting the access rights. That is a choke point, not a string.

**The target is therefore: prefer high-tamper-cost fields where they exist; where cheap fields are unavoidable, key on the portion the adversary's objective forces them to include.**

---

## 4. Applying it: before and after

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

Three conditions, three independent evasion paths:

1. **`Image`** — rename the binary. Free.
2. **`CommandLine|contains: '-enc'`** — PowerShell accepts any unambiguous prefix, so `-e <base64>` executes identically and does not match. Free.
3. **`ParentImage`** — the parent requirement is the most damaging. It is defeated by PPID spoofing, and it is also defeated by simply not using `cmd.exe`: a Word macro calling `Shell()` produces `WINWORD.EXE` as the direct parent, `wscript.exe` droppers produce `wscript.exe`, WMI execution produces `wmiprvse.exe`, and scheduled tasks produce `svchost.exe`.

The third point is worth stating plainly: **this version of the rule would not have detected the intrusion chain it was written from**, had the macro invoked PowerShell directly rather than via an intermediate shell.

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

Three changes:

- **`Image` → `OriginalFileName`.** Renaming the binary no longer evades. PE metadata survives a file copy; changing it breaks the signature. Note `pwsh.dll` — PowerShell 7 reports the DLL name, not the executable.
- **Regex requiring a payload, not a flag.** The pattern matches an abbreviated `-e*` parameter *followed by at least 15 base64 characters*. A naive `-e` substring match would fire on `-ExecutionPolicy` and `-ErrorAction`, two of the most common parameters in legitimate PowerShell. The signal is the parameter carrying a payload, not the parameter alone.
- **Parent requirement removed from the gate.** Encoded PowerShell with a long base64 payload is suspicious regardless of parent. Precision is traded for coverage. Parent process is better used to *weight severity* — escalate when the parent is an Office application, script host, or WMI provider — than as a hard condition that an adversary can simply route around.

---

## 5. Known limitations

This rule is `status: experimental` and has not been baselined against production volume. The expected dominant false-positive source is software deployment tooling: SCCM and Intune packages routinely wrap PowerShell in batch files and use `-EncodedCommand` specifically to avoid quote-escaping problems.
