---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-persistent-scripts-in-the-startup-directory.html
---

# Persistent Scripts in the Startup Directory [prebuilt-rule-1-0-2-persistent-scripts-in-the-startup-directory]

Identifies script engines creating files in the startup folder, or the creation of script files in the startup folder. Adversaries may abuse this technique to maintain persistence in an environment.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

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

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1643]

## Triage and analysis

## Investigating Persistent Scripts in the Startup Directory

The Windows Startup folder is a special folder in Windows. Programs added to this folder are executed during account
logon, without user interaction, providing an excellent way for attackers to maintain persistence.

This rule looks for shortcuts created by wscript.exe or cscript.exe, or js/vbs scripts created by any process.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Investigate other alerts related to the user/host in the last 48 hours.
- Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate
software installations.
- Determine if activity is unique by validating if other machines in the organization have similar entries.
- Retrieve the script file:
  - Use a sandboxed malware analysis system to perform analysis.
    - Observe attempts to contact external domains and addresses.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- There is a low possibility of benign legitimate scripts being added to Startup folders. Validate whether this activity
is benign.


## Related rules

- Suspicious Startup Shell Folder Modification - c8b150f0-0164-475b-a75e-74b47800a9ff
- Startup Folder Persistence via Unsigned Process - 2fba96c0-ade5-4bce-b92f-a5df2509da3f

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement any temporary network rules, procedures, and segmentation required to contain the malware.
  - Immediately block the identified indicators of compromise (IoCs).
- Reset passwords for the user account and other potentially compromised accounts (email, services, CRMs, etc.).

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1902]

```js
file where event.type != "deletion" and user.domain != "NT AUTHORITY" and

  /* detect shortcuts created by wscript.exe or cscript.exe */
  (file.path : "C:\\*\\Programs\\Startup\\*.lnk" and
     process.name : ("wscript.exe", "cscript.exe")) or

  /* detect vbs or js files created by any process */
  file.path : ("C:\\*\\Programs\\Startup\\*.vbs",
               "C:\\*\\Programs\\Startup\\*.vbe",
               "C:\\*\\Programs\\Startup\\*.wsh",
               "C:\\*\\Programs\\Startup\\*.wsf",
               "C:\\*\\Programs\\Startup\\*.js")
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



