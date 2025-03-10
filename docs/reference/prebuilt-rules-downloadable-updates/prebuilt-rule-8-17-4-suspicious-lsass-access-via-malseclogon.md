---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-lsass-access-via-malseclogon.html
---

# Suspicious LSASS Access via MalSecLogon [prebuilt-rule-8-17-4-suspicious-lsass-access-via-malseclogon]

Identifies suspicious access to LSASS handle from a call trace pointing to seclogon.dll and with a suspicious access rights value. This may indicate an attempt to leak an LSASS handle via abusing the Secondary Logon service in preparation for credential access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.sysmon_operational-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html](https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.md)

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

## Investigation guide [_investigation_guide_4720]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious LSASS Access via MalSecLogon**

The Local Security Authority Subsystem Service (LSASS) is crucial for managing security policies and user authentication in Windows environments. Adversaries may exploit the Secondary Logon service to gain unauthorized access to LSASS, aiming to extract sensitive credentials. The detection rule identifies this threat by monitoring for unusual access patterns involving LSASS, specifically when the seclogon.dll is involved, indicating potential credential dumping activities.

**Possible investigation steps**

* Review the event logs for the specific event code "10" to gather more details about the process that triggered the alert, focusing on the time of occurrence and any associated user accounts.
* Examine the process details for "svchost.exe" to determine if it is running under an expected service or if there are any anomalies in its execution context, such as unusual parent processes or command-line arguments.
* Investigate the call trace involving "seclogon.dll" to understand the sequence of events leading to the LSASS access, and check for any other suspicious modules or DLLs loaded in the process.
* Analyze the granted access value "0x14c0" to confirm if it aligns with typical access patterns for legitimate processes interacting with LSASS, and identify any deviations that could indicate malicious intent.
* Correlate the alert with other security events or logs from the same host or user account to identify any patterns or additional indicators of compromise, such as failed login attempts or other suspicious process activities.
* Check for any recent changes or updates to the system that might explain the unusual behavior, such as software installations, patches, or configuration changes that could affect the Secondary Logon service or LSASS.

**False positive analysis**

* Legitimate administrative tools or scripts that require access to LSASS for system management tasks may trigger this rule. Users can create exceptions for known tools by excluding specific process names or paths that are verified as safe.
* Security software or endpoint protection solutions that perform regular scans and require access to LSASS might be flagged. Coordinate with security vendors to identify these processes and exclude them from the rule.
* System updates or patches that involve the Secondary Logon service could cause temporary access patterns that mimic suspicious behavior. Monitor update schedules and temporarily adjust the rule to prevent false alerts during these periods.
* Custom enterprise applications that utilize the Secondary Logon service for legitimate purposes may inadvertently match the rule criteria. Work with application developers to understand these access patterns and whitelist the associated processes.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes associated with svchost.exe that are accessing LSASS with the identified suspicious access rights.
* Conduct a thorough review of user accounts and privileges on the affected system to identify any unauthorized changes or access.
* Reset passwords for all accounts that may have been compromised, focusing on high-privilege accounts first.
* Collect and preserve relevant logs and forensic data from the affected system for further analysis and potential legal action.
* Escalate the incident to the security operations center (SOC) or incident response team for a comprehensive investigation and to determine the full scope of the breach.
* Implement additional monitoring and alerting for similar suspicious activities involving LSASS and seclogon.dll to enhance detection capabilities.


## Setup [_setup_1512]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_5675]

```js
process where host.os.type == "windows" and event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* seclogon service accessing lsass */
  winlog.event_data.CallTrace : "*seclogon.dll*" and process.name : "svchost.exe" and

   /* PROCESS_CREATE_PROCESS & PROCESS_DUP_HANDLE & PROCESS_QUERY_INFORMATION */
  winlog.event_data.GrantedAccess == "0x14c0"
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



