---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-credential-access-via-lsass-memory-dump.html
---

# Potential Credential Access via LSASS Memory Dump [prebuilt-rule-8-17-4-potential-credential-access-via-lsass-memory-dump]

Identifies suspicious access to LSASS handle from a call trace pointing to DBGHelp.dll or DBGCore.dll, which both export the MiniDumpWriteDump method that can be used to dump LSASS memory content in preparation for credential access.

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

* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)
* [https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper](https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic:Execution
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 311

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4739]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Credential Access via LSASS Memory Dump**

LSASS (Local Security Authority Subsystem Service) is crucial for managing Windows security policies and storing sensitive data like user credentials. Adversaries exploit this by using tools that leverage MiniDumpWriteDump from libraries like DBGHelp.dll to extract credentials. The detection rule identifies suspicious LSASS access by monitoring for these libraries in call traces, excluding legitimate crash handlers, thus flagging potential credential theft attempts.

**Possible investigation steps**

* Review the process details associated with the alert, focusing on the process name, executable path, and parent process to determine if the process accessing LSASS is legitimate or suspicious.
* Examine the call trace details to confirm the presence of DBGHelp.dll or DBGCore.dll, which are indicative of potential credential dumping attempts.
* Check for any recent crash reports or legitimate use of WerFault.exe, WerFaultSecure.exe, or similar processes that might explain the LSASS access as a non-malicious event.
* Investigate the user account context under which the suspicious process is running to assess if it aligns with expected behavior or if it indicates potential compromise.
* Correlate the event with other security logs or alerts to identify any related suspicious activities, such as unauthorized access attempts or lateral movement within the network.
* Assess the risk and impact by determining if any sensitive credentials could have been exposed, and consider isolating the affected system to prevent further compromise.

**False positive analysis**

* Legitimate crash handlers like WerFault.exe may access LSASS during system crashes. To prevent these from being flagged, ensure that the rule excludes processes such as WerFault.exe, WerFaultSecure.exe, and their SysWOW64 counterparts.
* Debugging tools used by developers or IT administrators might trigger this rule if they access LSASS for legitimate purposes. Consider creating exceptions for known and trusted debugging tools within your environment.
* Security software or endpoint protection solutions may perform similar actions as part of their normal operations. Verify with your security vendor and exclude these processes if they are confirmed to be benign.
* Automated system diagnostics or maintenance scripts that interact with LSASS for health checks could be misidentified. Review and whitelist these scripts if they are part of routine system management tasks.
* Ensure that any custom or third-party applications that require access to LSASS for legitimate reasons are documented and excluded from the rule to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further credential access or lateral movement by the adversary.
* Terminate any suspicious processes that are accessing the LSASS memory, especially those involving DBGHelp.dll or DBGCore.dll, to stop the credential dumping activity.
* Conduct a thorough review of the affected system’s security logs to identify any unauthorized access or changes, focusing on event code "10" and call traces involving LSASS.
* Change passwords for all accounts that were active on the affected system, prioritizing high-privilege accounts, to mitigate the risk of compromised credentials being used.
* Restore the affected system from a known good backup to ensure that any malicious changes or tools are removed.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other systems may be affected.
* Implement enhanced monitoring and alerting for similar suspicious activities, focusing on LSASS access and the use of MiniDumpWriteDump, to improve detection and response capabilities.


## Setup [_setup_1525]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_5694]

```js
process where host.os.type == "windows" and event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* DLLs exporting MiniDumpWriteDump API to create an lsass mdmp*/
  winlog.event_data.CallTrace : ("*dbghelp*", "*dbgcore*") and

   /* case of lsass crashing */
  not process.executable : (
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\System32\\WerFaultSecure.exe"
      )
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

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)



