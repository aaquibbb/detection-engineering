# Detecting Browser Credential Theft: A Two-Layer Approach

**Rule:** `file_event_win_browser_credential_store_copied.yml`
**Technique:** T1555.003 Credentials from Web Browsers

---

## Summary

Infostealers are one of the highest-impact commodity threats facing financial
institutions, because the thing they steal (a live browser session cookie) walks
straight past multi-factor authentication. This write-up covers a first-layer
detection for browser credential theft, why it is deliberately brittle, the two
ways it is evaded, and the robust second layer that is intended to sit alongside
it.

The honest position up front: the rule in this repo is the cheap, brittle layer.
It catches the common case and is documented as such. The value here is in
understanding *why* it is built this way and what completes it.

---

## 1. Why this matters in finance

Browser credential theft is not finance-specific as a technique, but its impact
is concentrated there.

CrowdStrike's 2026 Financial Services report found that hands-on-keyboard
intrusions against financial institutions rose 43% globally and 48% in North
America over two years, driven by adversaries exploiting trusted identities and
SaaS applications to bypass legacy defences. VentureBeat's coverage of the same
report framed the dominant pattern bluntly: the attack dominating financial
services does not steal passwords, it resets MFA and steals the token.

That is the whole argument for prioritising cookie theft. A stolen password is
often useless against a hardware token. A stolen session cookie is an already
authenticated session: it reproduces the user's logged-in state without ever
touching the login flow, so MFA never fires. In a bank or a trading platform the
window between cookie theft and financial loss is minutes.

The rule reflects this by treating cookie stores (`Cookies`) with the same
weight as password stores (`Login Data`), and the intended production tuning
weights cookie access higher.

The triggering incident was real and recent: in July 2026 Darktrace observed a
fake Google Gemini installer delivering the Vidar infostealer in an EMEA finance
environment, with Defender for Endpoint subsequently confirming theft of browser
credentials. The lure was novel; the credential-theft behaviour was not, which
is exactly why detecting the behaviour rather than the lure is the right call.

---

## 2. The telemetry problem

The instinctive detection is "a non-browser process reads `Login Data`." That
runs into a wall: **Sysmon has no file-read event.** Sysmon EID 11 is
`FileCreate`; it fires on writes, not reads. Microsoft's Defender
`DeviceFileEvents` table is documented as covering file creation and
modification, and Microsoft does not publish the full `ActionType` list, so read
coverage cannot be assumed without testing in a live tenant.

Rather than build on telemetry that may not exist, the detection pivots to a
behaviour that *is* logged. Chrome holds `Login Data` locked while running, so
the typical stealer copies the file to a temporary location and reads the copy.
A copy is a file **creation**, and that is captured by both Sysmon EID 11 and
`DeviceFileEvents`.

So the detection target becomes: a credential-store filename created outside a
legitimate browser profile directory. Nothing legitimate writes Chrome's
`Login Data` into `%TEMP%`.

---

## 3. The rule, and why it is brittle by design

```yaml
detection:
    selection_file:
        TargetFilename|endswith:
            - '\Login Data'
            - '\Cookies'
            - '\logins.json'
            - '\key4.db'
    filter_browser_dirs:
        TargetFilename|contains:
            - '\User Data\'
            - '\Mozilla\Firefox\Profiles\'
    condition: selection_file and not filter_browser_dirs
```

Match a credential filename; exclude the real browser profile paths. It converts
cleanly to Defender KQL and to other backends.

Every field this rule keys on is `TargetFilename`, which is fully
adversary-controlled: they choose the copy's name and destination. By the field
tamper-cost framework used elsewhere in this repo, that makes it a low-cost,
low-durability detection. That is acceptable here because this is the brittle
layer, whose job is to catch commodity stealers cheaply, not to resist a
motivated adversary.

---

## 4. How it is evaded (both proven by testing)

**Evasion 1: name a folder `User Data`.** The filter excludes any path
containing `\User Data\`. An attacker who copies the file to
`C:\Temp\User Data\Login Data` lands inside the exclusion and the rule stays
silent. The allowlist is, in effect, an instruction to the adversary: it tells
them exactly which folder name makes them invisible. Tested and confirmed: a
file at `C:\Temp\User Data\Login Data` does not fire.

**Evasion 2: read in place, leave no copy.** When the browser is not running the
file is not locked, and the stealer can open the original directly, or work
around the lock. No copy is created, so there is no file-creation event and
nothing for this rule to match. This is the fundamental limit of a
creation-based detection and cannot be tuned away.

Both are stated plainly rather than hidden. A detection that documents its blind
spots is more useful to the analyst who inherits it than one that pretends to be
complete.

---

## 5. The robust layer this is meant to pair with

The credentials inside `Login Data` are encrypted. On modern Chrome they are
protected by Windows DPAPI and, more recently, App-Bound Encryption where the
key is tied to the browser. Copying or reading the file yields ciphertext. To
use the credentials the stealer must decrypt them, which means calling DPAPI as
the logged-in user or defeating App-Bound Encryption (typically by injecting
into or impersonating the browser).

That decryption step is a choke point. The attacker has freedom of expression
over the file (rename it, relocate it, skip the copy) but not freedom of action
over the decryption (it has to happen, as that user, against that key). A
detection on the DPAPI/App-Bound decryption behaviour survives the two evasions
above, because it does not depend on a file appearing anywhere.

This gives a two-layer model:

- **Layer 1 (this rule):** credential file created outside a profile directory.
  Cheap, brittle, fires loud, catches the majority of commodity stealers that do
  not bother evading.
- **Layer 2 (future work):** the decryption behaviour. Expensive to write,
  requires richer telemetry, much harder to evade. This is the durable
  detection.

Shipping Layer 1 now with Layer 2 documented as the intended complement is
better than shipping one confused rule that tries and fails to be both.

---

## 6. Known limitations and shipping bar

`status: experimental`. Not baselined against production volume.

The dominant expected false positive is endpoint backup and profile-imaging
software, which copies user profiles (including these files) on a schedule,
across many hosts, under a service account. That volume-plus-host-count
signature is exactly what a baseline surfaces:

```kql
DeviceFileEvents
| where FolderPath endswith @"\Login Data"
    or FolderPath endswith @"\Cookies"
    or FolderPath endswith @"\logins.json"
    or FolderPath endswith @"\key4.db"
| where not(FolderPath contains @"\User Data\"
    or FolderPath contains @"\Mozilla\Firefox\Profiles\")
| summarize Hosts=dcount(DeviceName), Hits=count()
    by InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Hits desc
```

High host count plus high volume is infrastructure, not an adversary; those
processes become the allowlist. Until that baseline is run, this belongs as a
scheduled hunt, not an alert. `\Cookies` in particular is likely to be noisy and
should be reviewed against real data before it is trusted.
