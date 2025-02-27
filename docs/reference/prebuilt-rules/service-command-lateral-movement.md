---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/service-command-lateral-movement.html
---

# Service Command Lateral Movement [service-command-lateral-movement]

Identifies use of sc.exe to create, modify, or start services on remote hosts. This could be indicative of adversary lateral movement but will be noisy if commonly done by admins.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.network-*
* winlogbeat-*
* logs-windows.sysmon_operational-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_920]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Service Command Lateral Movement**

The Service Control Manager in Windows allows for the management of services, which are crucial for system operations. Adversaries exploit this by using `sc.exe` to manipulate services on remote systems, facilitating lateral movement. The detection rule identifies suspicious `sc.exe` usage by monitoring for service-related commands targeting remote hosts, which may indicate unauthorized access attempts. This rule helps differentiate between legitimate administrative actions and potential threats.

**Possible investigation steps**

* Review the process details to confirm the use of sc.exe, focusing on the process.entity_id and process.args fields to understand the specific service-related actions attempted.
* Examine the network activity associated with the sc.exe process, particularly the destination.ip field, to identify the remote host targeted by the command and assess if it is a legitimate administrative target.
* Check the event logs on the remote host for any corresponding service creation, modification, or start events to verify if the actions were successfully executed and to gather additional context.
* Investigate the user account associated with the sc.exe process to determine if it has the necessary permissions for such actions and if the account usage aligns with expected behavior.
* Correlate the alert with other recent alerts or logs involving the same process.entity_id or destination.ip to identify any patterns or additional suspicious activities that may indicate a broader attack campaign.

**False positive analysis**

* Routine administrative tasks using sc.exe on remote systems can trigger false positives. Identify and document regular maintenance schedules and responsible personnel to differentiate these from potential threats.
* Automated scripts or management tools that use sc.exe for legitimate service management may cause alerts. Review and whitelist these scripts or tools by their process entity IDs to reduce noise.
* Internal IT operations often involve creating or modifying services remotely. Establish a baseline of normal activity patterns and exclude these from alerts by setting exceptions for known IP addresses or user accounts.
* Software deployment processes that involve service configuration changes can be mistaken for lateral movement. Coordinate with software deployment teams to understand their processes and exclude these activities from detection.
* Regularly review and update the exclusion list to ensure it reflects current operational practices and does not inadvertently allow malicious activity.

**Response and remediation**

* Isolate the affected system from the network to prevent further lateral movement and unauthorized access to other systems.
* Terminate any suspicious `sc.exe` processes identified on the affected system to halt any ongoing malicious activity.
* Review and reset credentials for any accounts that were used in the suspicious `sc.exe` activity to prevent unauthorized access.
* Conduct a thorough examination of the affected system for any additional signs of compromise, such as unauthorized services or changes to existing services.
* Restore the affected system from a known good backup if any malicious modifications or persistent threats are detected.
* Implement network segmentation to limit the ability of adversaries to move laterally across the network in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_977]

```js
sequence by process.entity_id with maxspan = 1m
  [process where host.os.type == "windows" and event.type == "start" and
     (process.name : "sc.exe" or process.pe.original_file_name : "sc.exe") and
      process.args : "\\\\*" and process.args : ("binPath=*", "binpath=*") and
      process.args : ("create", "config", "failure", "start")]
  [network where host.os.type == "windows" and process.name : "sc.exe" and destination.ip != "127.0.0.1"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: System Services
    * ID: T1569
    * Reference URL: [https://attack.mitre.org/techniques/T1569/](https://attack.mitre.org/techniques/T1569/)

* Sub-technique:

    * Name: Service Execution
    * ID: T1569.002
    * Reference URL: [https://attack.mitre.org/techniques/T1569/002/](https://attack.mitre.org/techniques/T1569/002/)



