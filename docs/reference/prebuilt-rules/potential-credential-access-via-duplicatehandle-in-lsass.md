---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-credential-access-via-duplicatehandle-in-lsass.html
---

# Potential Credential Access via DuplicateHandle in LSASS [potential-credential-access-via-duplicatehandle-in-lsass]

Identifies suspicious access to an LSASS handle via DuplicateHandle from an unknown call trace module. This may indicate an attempt to bypass the NtOpenProcess API to evade detection and dump LSASS memory for credential access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.sysmon_operational-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/CCob/MirrorDump](https://github.com/CCob/MirrorDump)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 309

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_658]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Credential Access via DuplicateHandle in LSASS**

The Local Security Authority Subsystem Service (LSASS) is crucial for enforcing security policies and managing user credentials in Windows environments. Adversaries may exploit the DuplicateHandle function to access LSASS memory, bypassing traditional API calls to avoid detection. The detection rule identifies suspicious LSASS handle access attempts from unknown modules, flagging potential credential dumping activities.

**Possible investigation steps**

* Review the event logs for the specific event code "10" to gather more details about the suspicious activity, focusing on the process name "lsass.exe" and the granted access "0x40".
* Investigate the call trace details where the event data indicates "**UNKNOWN**" to identify any unknown or suspicious modules that may have initiated the DuplicateHandle request.
* Correlate the suspicious activity with other security events or alerts on the same host to determine if there are additional indicators of compromise or related malicious activities.
* Check the process tree and parent-child relationships of the lsass.exe process to identify any unusual or unauthorized processes that may have interacted with LSASS.
* Analyze the timeline of events to understand the sequence of actions leading up to and following the alert, which may help in identifying the adversary’s objectives or next steps.
* Review recent changes or updates to the system that might have introduced the unknown module or altered the behavior of legitimate processes.

**False positive analysis**

* Legitimate software or security tools that interact with LSASS for monitoring or protection purposes may trigger this rule. Users should identify and whitelist these trusted applications to prevent unnecessary alerts.
* System management or administrative scripts that perform legitimate operations on LSASS might be flagged. Review these scripts and, if verified as safe, add them to an exception list to reduce false positives.
* Custom in-house applications that require access to LSASS for valid reasons could be mistakenly identified. Conduct a thorough review of these applications and exclude them from the rule if they are deemed non-threatening.
* Security testing or penetration testing activities may mimic malicious behavior. Coordinate with security teams to recognize these activities and temporarily adjust the rule settings during testing periods to avoid false alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes associated with the unknown executable region accessing LSASS to halt potential credential dumping activities.
* Conduct a thorough memory analysis of the affected system to identify any malicious artifacts or indicators of compromise related to the DuplicateHandle exploitation.
* Reset credentials for all accounts that may have been accessed or compromised, prioritizing high-privilege accounts.
* Review and update endpoint protection configurations to ensure they are capable of detecting and blocking similar unauthorized access attempts in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for LSASS and related processes to detect any future attempts to exploit the DuplicateHandle function.


## Setup [_setup_419]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_700]

```js
process where host.os.type == "windows" and event.code == "10" and

 /* LSASS requesting DuplicateHandle access right to another process */
 process.name : "lsass.exe" and winlog.event_data.GrantedAccess == "0x40" and

 /* call is coming from an unknown executable region */
 winlog.event_data.CallTrace : "*UNKNOWN*"
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



