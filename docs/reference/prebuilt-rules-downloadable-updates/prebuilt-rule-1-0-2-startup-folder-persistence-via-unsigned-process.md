---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-startup-folder-persistence-via-unsigned-process.html
---

# Startup Folder Persistence via Unsigned Process [prebuilt-rule-1-0-2-startup-folder-persistence-via-unsigned-process]

Identifies files written or modified in the startup folder by unsigned processes. Adversaries may abuse this technique to maintain persistence in an environment.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 41

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1642]

## Triage and analysis

## Investigating Startup Folder Persistence via Unsigned Process

The Windows Startup folder is a special folder in Windows. Programs added to this folder are executed during account
logon, without user interaction, providing an excellent way for attackers to maintain persistence.

This rule looks for unsigned processes writing to the Startup folder locations.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Investigate other alerts related to the user/host in the last 48 hours.
- Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate
software installations.
- Determine if activity is unique by validating if other machines in the organization have similar entries.
- Retrieve the file:
  - Use a sandboxed malware analysis system to perform analysis.
    - Observe attempts to contact external domains and addresses.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- There is a high possibility of benign legitimate programs being added to Startup folders. This activity could be based
on new software installations, patches, or any kind of network administrator related activity. Before entering further
investigation, verify that this activity is not benign.

## Related rules

- Suspicious Startup Shell Folder Modification - c8b150f0-0164-475b-a75e-74b47800a9ff
- Persistent Scripts in the Startup Directory - f7c4dc5a-a58d-491d-9f14-9b66507121c0

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement any temporary network rules, procedures, and segmentation required to contain the malware.
  - Immediately block the identified indicators of compromise (IoCs).
- Remove malicious artifacts identified on the triage.
- Reset passwords for the user account and other potentially compromised accounts (email, services, CRMs, etc.).

## Rule query [_rule_query_1901]

```js
sequence by host.id, process.entity_id with maxspan=5s
  [process where event.type in ("start", "process_started") and process.code_signature.trusted == false and
  /* suspicious paths can be added here  */
   process.executable : ("C:\\Users\\*.exe",
                         "C:\\ProgramData\\*.exe",
                         "C:\\Windows\\Temp\\*.exe",
                         "C:\\Windows\\Tasks\\*.exe",
                         "C:\\Intel\\*.exe",
                         "C:\\PerfLogs\\*.exe")
   ]
   [file where event.type != "deletion" and user.domain != "NT AUTHORITY" and
    file.path : ("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
                 "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*")
   ]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Registry Run Keys / Startup Folder
    * ID: T1547.001
    * Reference URL: [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)



