---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/windows-service-installed-via-an-unusual-client.html
---

# Windows Service Installed via an Unusual Client [windows-service-installed-via-an-unusual-client]

Identifies the creation of a Windows service by an unusual client process. Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.x86matthew.com/view_post?id=create_svc_rpc](https://www.x86matthew.com/view_post?id=create_svc_rpc)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697)
* [https://github.com/atc-project/atomic-threat-coverage/blob/master/Atomic_Threat_Coverage/Logging_Policies/LP_0100_windows_audit_security_system_extension.md](https://github.com/atc-project/atomic-threat-coverage/blob/master/Atomic_Threat_Coverage/Logging_Policies/LP_0100_windows_audit_security_system_extension.md)
* [https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry](https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: System
* Resources: Investigation Guide

**Version**: 212

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1207]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Windows Service Installed via an Unusual Client**

Windows services are crucial for running background processes with elevated privileges. Adversaries exploit this by creating services to escalate privileges from administrator to SYSTEM. The detection rule identifies anomalies by flagging service installations initiated by atypical processes, excluding known legitimate services. This helps in spotting potential privilege escalation attempts by monitoring unusual client activity.

**Possible investigation steps**

* Review the event logs to identify the specific client process that initiated the service installation by examining the winlog.event_data.ClientProcessId and winlog.event_data.ParentProcessId fields.
* Investigate the parent process associated with the unusual client process to determine if it is a known legitimate application or potentially malicious.
* Check the winlog.event_data.ServiceFileName to verify the path and name of the service file, ensuring it is not a known legitimate service excluded in the query.
* Analyze the timeline of events around the service installation to identify any preceding suspicious activities or related alerts that might indicate a broader attack.
* Conduct a reputation check on the client process and service file using threat intelligence sources to assess if they are associated with known malicious activities.
* Examine the system for any additional indicators of compromise, such as unexpected network connections or changes to critical system files, that may suggest privilege escalation or lateral movement attempts.

**False positive analysis**

* Legitimate software installations or updates may trigger the rule if they create services using unusual client processes. To manage this, identify and whitelist these processes in the detection rule to prevent unnecessary alerts.
* System management tools like Veeam and PDQ Inventory are already excluded, but other similar tools might not be. Regularly review and update the exclusion list to include any additional legitimate tools used in your environment.
* Custom scripts or administrative tools that create services for maintenance or monitoring purposes can also cause false positives. Document these scripts and consider adding them to the exclusion list if they are verified as safe.
* Temporary or one-time service installations for troubleshooting or testing can be mistaken for threats. Ensure that such activities are logged and communicated to the security team to avoid confusion and unnecessary alerts.
* Changes in system configurations or updates to existing software might alter the behavior of legitimate processes, causing them to be flagged. Regularly review and adjust the detection rule to accommodate these changes while maintaining security integrity.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate the suspicious service and any associated processes identified by the alert to stop potential privilege escalation or malicious activity.
* Conduct a thorough review of the service’s configuration and associated files to identify any unauthorized changes or malicious code.
* Restore any altered or compromised system files from a known good backup to ensure system integrity.
* Change all administrator and SYSTEM account passwords on the affected system and any connected systems to prevent further unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach.
* Implement additional monitoring and logging on the affected system and similar environments to detect any recurrence of the threat or related suspicious activities.


## Setup [_setup_758]

**Setup**

The *Audit Security System Extension* logging policy must be configured for (Success) Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
System >
Audit Security System Extension (Success)
```


## Rule query [_rule_query_1235]

```js
configuration where host.os.type == "windows" and
  event.action == "service-installed" and
  (winlog.event_data.ClientProcessId == "0" or winlog.event_data.ParentProcessId == "0") and
  not winlog.event_data.ServiceFileName : (
    "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe",
    "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
    "%SystemRoot%\\system32\\Drivers\\Crowdstrike\\*-CsInstallerService.exe",
    "\"%windir%\\AdminArsenal\\PDQInventory-Scanner\\service-1\\PDQInventory-Scanner-1.exe\" "
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



