---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-windows-script-executing-powershell.html
---

# Windows Script Executing PowerShell [prebuilt-rule-1-0-2-windows-script-executing-powershell]

Identifies a PowerShell process launched by either cscript.exe or wscript.exe. Observing one of these Windows scripting processes executing a PowerShell script may be indicative of malicious activity.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Initial Access

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1611]

## Triage and analysis

## Investigating Windows Script Executing PowerShell

The Windows Script Host (WSH) is an Windows automation technology, which is ideal for non-interactive scripting needs,
such as logon scripting, administrative scripting, and machine automation.

Attackers commonly use WSH scripts as their initial access method, acting like droppers for second stage payloads, but
can also use them to download tools and utilities needed to accomplish their goals.

This rule looks for the spawn of the `powershell.exe` process with `cscript.exe` or `wscript.exe` as its parent process.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Investigate commands executed by the spawned PowerShell process.
- Retrieve the script file(s) involved:
  - Use a sandboxed malware analysis system to perform analysis.
    - Observe attempts to contact external domains and addresses.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
  - Manually analyze the script to determine if malicious capabilities are present.
- Determine how the script file was delivered (email attachment, dropped by other processes, etc.).
- Investigate other alerts related to the user/host in the last 48 hours.

## False positive analysis

- The usage of these script engines by regular users is unlikely. In the case of authorized benign true positives
(B-TPs), exceptions can be added.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement any temporary network rules, procedures, and segmentation required to contain the malware.
  - Immediately block the identified indicators of compromise (IoCs).
- Remove and block malicious artifacts identified on the triage.
- If the malicious file was delivered via phishing:
  - Block the email sender from sending future emails.
  - Block the malicious web pages.
  - Remove emails from the sender from mailboxes.
- Reimage the host operating system and restore compromised files to clean versions.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1860]

```js
process where event.type in ("start", "process_started") and
  process.parent.name : ("cscript.exe", "wscript.exe") and process.name : "powershell.exe"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)



