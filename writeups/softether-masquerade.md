# Detecting SoftEther Masquerade: Metadata vs Location

**Rule:** `proc_creation_win_softether_masquerade_relocation.yml`
**Technique:** T1036.005 Masquerading: Match Legitimate Name or Location, T1572 Protocol Tunnelling
**Campaign:** Stage one of a detection series against CISA AA26-281A

---

## Summary

This is the first detection in a campaign built against a single current
intrusion chain: the China-nexus actor described in CISA advisory AA26-281A
(October 2026), who combines automated scanning with hands-on tooling to steal
data from victim networks. Rather than scatter unrelated rules, the campaign
takes one documented adversary and builds detection coverage stage by stage.

This rule covers the actor's persistence mechanism: legitimate SoftEther VPN
binaries, renamed and relocated to masquerade as Windows system processes. It
detects not SoftEther itself, but the **contradiction** that masquerading
creates — a binary whose metadata proves it is SoftEther, running from a
location where SoftEther is never installed.

---

## 1. Why a legitimate tool, and why rename it

SoftEther is a legitimate, signed, open-source VPN suite. That is exactly why
the actor uses it.

Writing custom tunnelling malware is expensive and noisy: EDR flags it, it has
no plausible reason to exist, and it lights up behavioural detectors. SoftEther
has none of those problems. It is known-good software, antivirus will not flag
it, and it does precisely what the actor needs — encrypted tunnelling for covert
remote access and exfiltration. Bringing a legitimate tool to do a malicious job
is living-off-the-land, and it is the actor's deliberate choice to evade
signature-based defence.

But using the real tool only solves half the problem. Antivirus will not flag
`vpnserver.exe`, but a defender reviewing process telemetry would still ask why a
VPN server is running on a finance workstation. So the actor renames the binary
to something that belongs on every Windows host — `svchost.exe`, `conhost.exe` —
and moves it out of its install directory. Now it is invisible to both layers:
AV does not flag it because it is genuinely SoftEther, and an analyst scanning
process names does not flag it because it looks like a system binary.

A precise note on vocabulary, because the actor does two different things at
different stages: they **exploit** public-facing Exchange to gain initial access
(attacking a vulnerability), then **abuse** legitimate SoftEther for persistence
(using intended functionality for a malicious end). This rule addresses the
second.

---

## 2. The detection is a comparison, not a match

The key insight: hiding from the analyst is what makes the binary detectable.

To evade name-based review, the actor must rename the file. But renaming the
file on disk does not change the PE version metadata compiled into it. The
`Product` field still reads `SoftEther VPN`. So the masquerade creates a
contradiction:

- **Metadata** (`Product`) says the binary **is** SoftEther.
- **Location** (`Image`) says it is running from somewhere SoftEther does **not**
  install.

Legitimate SoftEther never produces that contradiction — the real install runs
from its own directory under its own name. A masqueraded copy always does,
because to hide the name the actor had to move the file out of its install
folder.

```yaml
detection:
  selection:
    Product|contains: 'SoftEther'
  filter:
    Image|contains: '\SoftEther VPN'
  condition: selection and not filter
```

`selection` identifies the binary as SoftEther by metadata. `filter` excludes the
legitimate install location. `selection and not filter` leaves exactly the
copies that carry SoftEther metadata but run from outside the install path — the
masquerade.

Two deliberate field choices:

**`Product`, not filename.** The filename is what the attacker controls and
changes, so it cannot be the basis of detection. `Product` metadata is expensive
to change — it is compiled into the binary's version resource. Keying on the
tamper-expensive field is the same principle used throughout this repo.

**`Product|contains: 'SoftEther'`, not an enumerated binary list.** The whole
SoftEther suite (server, bridge, client, vpncmd, server manager) shares the
`SoftEther VPN` product string. Matching the shared metadata root covers every
component, including ones never seen, without maintaining a per-binary name list.
Verified against `vpncmgr_x64.exe`, which reports `Product: SoftEther VPN`.

**Filter by location, not by name.** The legitimate install is defined by *where*
it lives, not *what* it is called. The attacker changes the name but, by moving
the file to hide it, leaves it outside the install directory. The filter keys on
the folder fragment `\SoftEther VPN`, which matches the install root on any drive
and for any suite component, rather than anchoring to `C:\Program Files\` (which
would false-positive on non-C: drives, `Program Files (x86)`, and non-English
Windows).

---

## 3. Where this sits on the kill chain

The AA26-281A chain, in order:

1. Reconnaissance — external vulnerability scanning (no endpoint visibility)
2. Initial access — Exchange exploitation, XSS credential harvest, password spray
3. **Persistence — renamed/relocated SoftEther ← this rule**
4. Credential access — DCSync against Active Directory
5. Collection and exfiltration — Exchange/M365 email theft

This rule fires at stage 3, the earliest point the actor is visible in endpoint
process telemetry. Stages 1 and 2 live in network and identity telemetry
(sign-in logs, web-server logs) and are out of scope for a process-creation rule;
they are candidates for later campaign entries built on those data sources.
Detecting at the persistence-establishment moment matters because it is the
difference between catching the intrusion as the tunnel is planted versus weeks
later after exfiltration.

---

## 4. How it is evaded

**Folder-name allowlist bypass.** The filter excludes any path containing
`\SoftEther VPN`. An attacker who drops the renamed binary into a folder they
name `C:\Temp\SoftEther VPN\` lands inside the exclusion and is not detected.
This is largely self-defeating for this adversary — naming the folder SoftEther
undoes the point of hiding the binary among system files — but it is a real gap
and is noted rather than hidden.

**Metadata stripping (defeats the rule entirely).** SoftEther is open source. An
actor who recompiles it with the version resource stripped or altered produces a
binary with a blank or forged `Product` field, which `selection` never matches.
This rule therefore catches the rename-and-relocate masquerade — the common,
lazy case, which is what most operators do — but not an actor who rebuilds from
source. That is the brittle/robust boundary: this is the brittle layer. A robust
layer would key on SoftEther's network protocol signature or loaded modules,
which survive recompilation; that is a candidate for a later campaign entry.

**Linux.** `Product` is a Windows PE concept. SoftEther also runs on Linux (ELF),
where no such metadata field exists, so this rule has no Linux equivalent and is
correctly scoped `product: windows`. Linux SoftEther detection would need a
different basis — binary hash, compiled strings, or network behaviour.

---

## 5. Validation and known limitations

`status: experimental`. The rule parses and its logic is verified by inspection:
`selection` matches SoftEther metadata, `filter` excludes the install path, and
the condition leaves the mismatch. The `Product: SoftEther VPN` string is
confirmed against a real binary (`vpncmgr_x64.exe`).

Not yet validated against live telemetry. Before this is promoted to `test`:
install SoftEther, confirm the exact default install path matches the
`\SoftEther VPN` filter, then copy a SoftEther binary to a non-standard location,
rename it, run it, and confirm the rule fires on the resulting Sysmon EID 1 while
a normal install does not.

False positives to baseline: SoftEther portable edition (no formal install, runs
from a user directory or USB, so legitimately outside the filtered path);
non-standard admin installs; forensic tooling that relocates the binary. All are
rare, but the portable-edition case is the most likely genuine trigger and should
be confirmed against the estate before this ships as an alert rather than a hunt.
