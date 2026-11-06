# Detecting DCSync: Secret Replication From Where It Shouldn't Come

**Rule:** `security_win_dcsync_replication_from_non_dc.yml`
**Technique:** T1003.006 OS Credential Dumping: DCSync
**Campaign:** Stage 4 of the detection series against CISA AA26-281A (credential access)

---

## Summary

This is the fourth stage in a detection campaign built against the China-nexus
actor in CISA advisory AA26-281A. Stage 3 caught the actor's SoftEther
persistence; this stage catches credential access via DCSync.

DCSync is one of the highest-impact techniques in Active Directory. An attacker
with sufficient privilege asks a domain controller to *replicate* directory
secrets - and walks away with password hashes for the entire domain, including
`krbtgt` (which enables Golden Tickets) and every domain admin. No code runs on
the DC, nothing is written to its disk. It looks like normal replication.

The detection rests on a single contradiction: a request to replicate domain
secrets, coming from an account that is not a domain controller.

---

## What DCSync is, and why it is so dangerous

Domain controllers keep themselves in sync by replicating directory changes to
each other through the Directory Replication Service. Replicating *secret*
attributes - password hashes - requires two extended rights:
`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`.

DCSync abuses exactly this mechanism. The attacker, using a compromised account
that holds (or has been granted) those rights, asks a DC to replicate secrets to
them as though they were another DC. The DC complies. The result is domain-wide
credential theft performed through a legitimate protocol, which is why it evades
controls that look for malware or disk activity on the DC.

For this actor, DCSync is the credential-access step that turns a foothold into
full domain compromise, feeding the lateral movement and data theft that follow.

---

## The detection is a two-field contradiction

The signal lives in Windows Security Event ID 4662 (an operation on a directory
object), logged on the domain controller. Two fields together make the case:

- **`Properties`** contains one of the replication-rights GUIDs. This proves a
  request to replicate secrets was made.
- **`SubjectUserName`** is not a domain controller. This proves it came from
  something that has no legitimate reason to replicate.

```yaml
detection:
    selection:
        EventID: 4662
        AccessMask: '0x100'
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # Get-Changes
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # Get-Changes-All (secrets)
            - '89e95b76-444d-4c62-991a-0facbeda640c'   # Get-Changes-In-Filtered-Set
    filter_dc_accounts:
        SubjectUserName|endswith: '$'
    condition: selection and not filter_dc_accounts
```

Legitimate replication produces this event constantly - but always from a DC
machine account. Filtering machine accounts (which end in `$`) removes the
legitimate population and leaves the requests that shouldn't exist.

---

## Why these fields: tamper cost on a new log source

The same field-selection discipline used across this repo applies here, and
DCSync is close to a best case for it.

- **The replication GUIDs are immutable schema constants.** `1131f6ad-...` means
  "Get-Changes-All" in every Active Directory on earth - it is defined in the
  schema, globally, permanently. The attacker cannot change what GUID represents
  the right to pull secrets, and they cannot perform DCSync without requesting
  it. This is the highest-durability field a detection can key on: forced *and*
  universal.
- **`AccessMask` (`0x100`, Control Access) is forced** by the operation -
  extended rights are exercised through Control Access, not chosen by the caller.
  It is a tightener; the GUID carries the detection. If validation ever shows it
  varies, it should be dropped rather than allowed to cause a miss.
- **`SubjectUserName` is the only attacker-influenced field, and only weakly.**
  The attacker chooses which compromised account to run DCSync from, but cannot
  make it a legitimate domain controller without first compromising a DC. So it
  is used as the filter, not the signal: exclude the accounts the attacker
  cannot cheaply become.

A note on telemetry, because this is not Sysmon: 4662 lives in the Windows
Security log (`service: security`), and although Event Viewer groups its fields
into Subject / Object / Operation sections, the raw fields are flat -
`SubjectUserName`, `Properties`, `AccessMask`, `ObjectServer`, with no nesting.

---

## Blind spots

- **DCSync from a compromised domain controller.** If the attacker already
  controls a DC, they can replicate from it under a legitimate DC account, and
  the machine-account filter hides them. At that point, however, they already
  hold the domain, so DCSync is neither distinguishable nor necessary.
- **DCSync from a compromised machine account.** The filter excludes *all*
  accounts ending in `$`, not just domain controllers, as a practical proxy. A
  DCSync run from a non-DC computer account that has been granted replication
  rights would therefore evade it. Rare, but real, and the cost of using a
  cheap proxy for "is a DC."
- **Legitimate non-DC replicators.** Azure AD Connect and some backup / identity
  tooling replicate under service accounts that do not end in `$`, so they fire
  and must be allowlisted per environment. This is a correct match with a benign
  cause - allowlist the known account, do not weaken the rule.

---

## Validation and status

`status: experimental`. The rule parses, and its logic is verified against
representative events: it fires on a replication-of-secrets request from a user
or service account, and stays quiet on the same request from a DC machine
account, on other 4662 operations, and on other event IDs.

Not yet validated against captured telemetry. DCSync does not require a domain
controller to validate - EVTX-ATTACK-SAMPLES contains a captured 4662 DCSync
event that can be run through Chainsaw:

```
chainsaw hunt <dcsync_sample.evtx> -s <rules_dir> --mapping sigma-event-logs-all.yml --csv --output dcsync_results
```

Confirm the rule fires on the captured event and that the sample's
`SubjectUserName` is a non-DC account. Promotion to `test` follows that run; to
`stable`, a production baseline that identifies and allowlists the environment's
legitimate non-DC replicators (Azure AD Connect and similar).
EOF
echo "write-up written"
ls -la writeups/dcsync-non-dc.md