---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-remote-file-download-via-script-interpreter.html
---

# Remote File Download via Script Interpreter [prebuilt-rule-1-0-2-remote-file-download-via-script-interpreter]

Identifies built-in Windows script interpreters (cscript.exe or wscript.exe) being used to download an executable file from a remote destination.

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
* Command and Control

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1505]

## Triage and analysis

## Investigating Remote File Download via Script Interpreter

The Windows Script Host (WSH) is a Windows automation technology, which is ideal for non-interactive scripting needs,
such as logon scripting, administrative scripting, and machine automation.

Attackers commonly use WSH scripts as their initial access method, acting like droppers for second stage payloads, but
can also use them to download tools and utilities needed to accomplish their goals.

This rule looks for DLLs and executables downloaded using `cscript.exe` or `wscript.exe`.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Retrieve the script file and the executable involved:
  - Use a sandboxed malware analysis system to perform analysis.
    - Observe attempts to contact external domains and addresses.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
  - Manually analyze the script to determine if malicious capabilities are present.
- Investigate whether the potential malware ran successfully, is active on the host, or was stopped by defenses.
- Investigate other alerts related to the user/host in the last 48 hours.
- Check for similar behavior in other hosts on the environment.

## False positive analysis

- The usage of these script engines by regular users is unlikely. In the case of authorized benign true positives
(B-TPs), exceptions can be added.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement any temporary network rules, procedures, and segmentation required to contain the malware.
- Remove and block malicious artifacts identified on the triage.
- Reimage the host operating system and restore compromised files to clean versions.

## Rule query [_rule_query_1740]

```js
sequence by host.id, process.entity_id
  [network where process.name : ("wscript.exe", "cscript.exe") and network.protocol != "dns" and
   network.direction : ("outgoing", "egress") and network.type == "ipv4" and destination.ip != "127.0.0.1"
  ]
  [file where event.type == "creation" and file.extension : ("exe", "dll")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



