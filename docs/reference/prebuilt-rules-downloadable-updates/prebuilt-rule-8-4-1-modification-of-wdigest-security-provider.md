---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-modification-of-wdigest-security-provider.html
---

# Modification of WDigest Security Provider [prebuilt-rule-8-4-1-modification-of-wdigest-security-provider]

Identifies attempts to modify the WDigest security provider in the registry to force the user’s password to be stored in clear text in memory. This behavior can be indicative of an adversary attempting to weaken the security configuration of an endpoint. Once the UseLogonCredential value is modified, the adversary may attempt to dump clear text passwords from memory.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.csoonline.com/article/3438824/how-to-detect-and-halt-credential-theft-via-windows-wdigest.html](https://www.csoonline.com/article/3438824/how-to-detect-and-halt-credential-theft-via-windows-wdigest.md)
* [https://www.praetorian.com/blog/mitigating-mimikatz-wdigest-cleartext-credential-theft?edition=2019](https://www.praetorian.com/blog/mitigating-mimikatz-wdigest-cleartext-credential-theft?edition=2019)
* [https://frsecure.com/compromised-credentials-response-playbook](https://frsecure.com/compromised-credentials-response-playbook)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Investigation Guide
* Elastic Endgame

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2696]

## Triage and analysis

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
- Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for
prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Determine if credential dumping tools were run on the host, and retrieve and analyze suspicious executables:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled task creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
- Use process name, command line, and file hash to search for occurrences on other hosts.
- Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the target
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
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Reimage the host operating system and restore compromised files to clean versions.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_3086]

```js
registry where event.type : ("creation", "change") and
    registry.path : (
        "HKLM\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential",
        "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential"
    ) and registry.data.strings : ("1", "0x00000001") and
    not (process.executable : "?:\\Windows\\System32\\svchost.exe" and user.id : "S-1-5-18")
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



