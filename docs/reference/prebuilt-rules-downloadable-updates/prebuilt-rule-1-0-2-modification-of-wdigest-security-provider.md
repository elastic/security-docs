---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-modification-of-wdigest-security-provider.html
---

# Modification of WDigest Security Provider [prebuilt-rule-1-0-2-modification-of-wdigest-security-provider]

Identifies attempts to modify the WDigest security provider in the registry to force the user’s password to be stored in clear text in memory. This behavior can be indicative of an adversary attempting to weaken the security configuration of an endpoint. Once the UseLogonCredential value is modified, the adversary may attempt to dump clear text passwords from memory.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.csoonline.com/article/3438824/how-to-detect-and-halt-credential-theft-via-windows-wdigest.html](https://www.csoonline.com/article/3438824/how-to-detect-and-halt-credential-theft-via-windows-wdigest.md)
* [https://www.praetorian.com/blog/mitigating-mimikatz-wdigest-cleartext-credential-theft?edition=2019](https://www.praetorian.com/blog/mitigating-mimikatz-wdigest-cleartext-credential-theft?edition=2019)
* [https://frsecure.com/compromised-credentials-response-playbook](https://frsecure.com/compromised-credentials-response-playbook)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1517]

## Triage and analysis.

## Investigating Modification of WDigest Security Provider

In Windows XP, Microsoft added support for a protocol known as WDigest. The WDigest protocol allows clients to send
cleartext credentials to Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) applications
based on RFC 2617 and 2831. Windows versions up to 8 and 2012 store logon credentials in memory in plaintext by default,
which is no longer the case with newer Windows versions.

Still, attackers can force WDigest to store the passwords insecurely on the memory by modifying the
`HKLM\SYSTEM\*ControlSet*\Control\SecurityProviders\WDigest\UseLogonCredential` registry key. This activity is
commonly related to the execution of credential dumping tools.

### Possible investigation steps

- It is unlikely that the monitored registry key was modified legitimately in newer versions of Windows. Analysts should
treat any activity triggered from this rule with high priority as it typically represents an active adversary.
- Investigate the script execution chain (parent process tree).
- Investigate other alerts related to the user/host in the last 48 hours.
- Determine if credential dumping tools were run on the host and if any suspicious tool is found:
  - Retrieve the file.
  - Use a sandboxed malware analysis system to perform analysis.
  - Observe attempts to contact external domains and addresses.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
- Use process name, command line, and file hash to search for other compromised hosts.
- Scope potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the target
host after the registry modification.

## False positive analysis

- This modification should not happen legitimately. Any potential benign true positive (B-TP) should be mapped and
monitored by the security team, as these modifications expose the entire domain to credential compromises and
consequently unauthorized access.

## Related rules

- Mimikatz Powershell Module Activity - ac96ceb8-4399-4191-af1d-4feeac1f1f46

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Disable user account’s ability to log in remotely.
- Reset the password for the user account and other potentially compromised accounts (email, services, CRMs, etc.).
- Reimage the host operating system and restore compromised files to clean versions.


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1753]

```js
registry where event.type : ("creation", "change") and
    registry.path :
        "HKLM\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential"
    and registry.data.strings : ("1", "0x00000001")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)



