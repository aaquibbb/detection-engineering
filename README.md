# Detection Engineering 🔎🕵🏻

Sigma rules with the reasoning behind them.

One rule per week, each with a write-up covering **why those fields were chosen**, **how an adversary evades it**, and **what legitimate activity sets it off**. Where a rule hasn't been validated against production data, it says so.

The goal isn't volume. Public rule dumps are easy to produce and tell a reader nothing about whether the author can think. The write-ups are the point; the rules are the artifact they're reasoning about.

---

## Rules

| # | Rule | Technique | Status | Write-up |
|---|---|---|---|---|
| 01 | [Encoded PowerShell Command Execution](rules/proc_creation_win_powershell_encoded_command.yml) | T1059.001, T1027 | `experimental` | [Field Selection](writeups/field-selection.md) |
| 02 | [Browser Credential Store Copied Outside Profile Directory](rules/file_event_win_browser_credential_store_copied.yml) | T1555.003 | `experimental` | [Field Selection](writeups/browser-credential-theft.md.md) |
---

## Approach

**Choose fields by tamper cost, not by provenance.** `ParentImage` is derived by the kernel and still trivially spoofed via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. `OriginalFileName` sits in PE metadata and can't be altered without breaking the binary's signature. Where a cheap field is unavoidable, the logic keys on the part the adversary's objective forces them to include — the payload, not the flag.

**Every `and` is a place the rule breaks.** Extra conditions buy precision and cost coverage. A required parent process or a specific filename is something an adversary routes around, and gets documented as such rather than counted as a win. Conditions useful for triage but too brittle to gate on are noted as severity weightings instead of being baked into the match.

**Say what hasn't been tested.** A rule marked `stable` that has never seen production data is worse than an honest `experimental`.

---

## Conventions

**Naming** — `<category>_<product>_<description>.yml`, matching SigmaHQ.

**Log source** — `category` + `product` rather than `service`, so rules stay portable across Sysmon, Defender for Endpoint, and the Windows Security log.

**Status**

| Status | Meaning |
|---|---|
| `experimental` | Logic written, not validated against production volume |
| `test` | Validated in a lab; baselining incomplete |
| `stable` | Baselined, tuned, ready to ship as an alert |

**False positives** — every rule names specific FP sources. `Unknown` isn't acceptable for common telemetry like process creation on a scripting engine.

---

## Validation

```bash
sigma check rules/
sigma convert -t kusto rules/proc_creation_win_powershell_encoded_command.yml
```

---

## References

- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [LOLBAS](https://lolbas-project.github.io/)
