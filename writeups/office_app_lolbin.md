# Office Spawning LOLBins: Building Tunability Into the Rule

**Rule:** `proc_creation_win_office_spawning_lolbin.yml`
**Technique:** T1204.002 User Execution: Malicious File, T1059 Command and Scripting Interpreter

---

## Summary

"Office application spawns a shell" is one of the most-written detections in
existence. The naive version — Word's child is cmd or PowerShell — exists a
hundred times over. This write-up is not about the behaviour, which is well
known. It is about two design decisions that make a rule for that behaviour
worth maintaining: splitting the child processes into confidence tiers so the
rule is tunable without being rewritten, and stating plainly the attack class
the rule cannot see.

---

## 1. The behaviour

A user opens a macro-enabled document. The macro executes, and to do anything
useful it launches another process. That child process, spawned by an Office
application, is the signal. Word editing a document does not launch `mshta` or
`regsvr32`; if it does, code embedded in the document is running.

The parents are the Office applications that run macros or embedded code:
`winword.exe`, `excel.exe`, `powerpnt.exe`, `msaccess.exe`, `mspub.exe`,
`onenote.exe`. OneNote is included deliberately — it was a significant malware
delivery vector in 2023–2024. (The process is `onenote.exe`; `onenotem.exe` is
the screen-clipper helper and is not the one that spawns payloads, an easy and
silent mistake to make.)

---

## 2. The design decision: tier the children by confidence

The obvious implementation is one flat list of suspicious children. The problem
is that the children are not equally suspicious.

`mshta`, `regsvr32`, `certutil`, `bitsadmin`, and the script hosts (`wscript`,
`cscript`) have almost no legitimate reason to be spawned by an Office
application. When they are, it is nearly always malicious — a download LOLBin
fetching stage two, or a scriptlet executing.

`cmd` and `powershell` are different. Office does spawn them legitimately:
enterprise templates with sanctioned macros, internal automation, add-ins. They
are still worth detecting from an Office parent, but they will generate false
positives where the high-confidence set will not.

A flat list hides this distinction. So the rule splits the children into two
named blocks:

```yaml
detection:
    selection_office_apps:
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
            - '\powerpnt.exe'
            - '\msaccess.exe'
            - '\mspub.exe'
            - '\onenote.exe'
    selection_high_confidence:
        Image|endswith:
            - '\mshta.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\certutil.exe'
            - '\bitsadmin.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    selection_low_confidence:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
    condition: selection_office_apps and (selection_high_confidence or selection_low_confidence)
```

This buys two things that a flat list does not:

- **Tunability.** When baselining shows the low-confidence tier is too noisy for
  the estate, it is removed by deleting one block, not by surgically editing
  items out of a shared list. The high-confidence detection keeps working
  untouched.
- **Self-documentation.** The structure records the fidelity judgement. Anyone
  reading the rule can see which children are considered near-certain and which
  are provisional, without having to ask the author.

`rundll32` sits in the high-confidence tier but is its softest member: Office
does invoke it legitimately for some add-in and printing paths. It is the entry
most likely to surface in a baseline and the first high-confidence candidate to
reconsider. `cmd` is the softest member of the low-confidence tier and the first
thing to cut under tuning pressure overall.

---

## 3. What this rule cannot see

The rule detects a macro that spawns a visible child process. Not every macro
does.

A macro can execute code via WMI, in which case the child's parent is
`wmiprvse.exe`, not the Office application, and this rule sees nothing. It can
use a COM object to the same effect. It can spoof the parent PID so the child
appears to descend from something benign. In all three cases the Office-parent
condition never matches.

This is the same evasion class documented for the encoded-PowerShell rule in
this repo: a hard condition on the parent process is defeated by any technique
that changes or hides the parent. The rule catches the large population of
commodity maldocs that simply call `Shell()` or `CreateObject("WScript.Shell")`,
which is most of them. It does not catch an operator who has read this write-up.

Closing that gap means detecting the execution primitive directly. The WMI
provider spawning a scripting engine, or module loads characteristic of
in-memory execution, rather than relying on the parent-child chain. That is a
separate, more expensive detection and is noted here as the honest boundary of
this one rather than solved inside it.

---

## 4. Validation and known limitations

`status: experimental`. The rule parses, converts, and its logic has been
verified against true-positive and true-negative cases (Word→mshta and
Excel→regsvr32 fire; non-Office parents and benign children do not). It has not
yet been fired against live Sysmon telemetry, which is the step required before
it earns `test` status.

Two findings from building it, both worth carrying to every rule:

**Case sensitivity.** Sysmon records process paths in mixed case (`WINWORD.EXE`).
Sigma's `endswith` is case-insensitive, so the lowercase values in this rule
match correctly. But whether that holds depends on the target backend — a
case-sensitive SIEM matching lowercase rule values against uppercase telemetry
would silently never fire. This must be confirmed per backend, not assumed.


**False positives to baseline before shipping as an alert:** Office add-ins
invoking `rundll32`; sanctioned enterprise macros shelling to `cmd`/`powershell`;
software that embeds and drives the Office engine. The low-confidence tier is the
expected dominant source and is structured to be removable if the baseline
demands it.
