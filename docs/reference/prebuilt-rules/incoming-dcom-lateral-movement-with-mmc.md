---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/incoming-dcom-lateral-movement-with-mmc.html
---

# Incoming DCOM Lateral Movement with MMC [incoming-dcom-lateral-movement-with-mmc]

Identifies the use of Distributed Component Object Model (DCOM) to run commands from a remote host, which are launched via the MMC20 Application COM Object. This behavior may indicate an attacker abusing a DCOM application to move laterally.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-endpoint.events.network-*
* logs-windows.sysmon_operational-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_426]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Incoming DCOM Lateral Movement with MMC**

Distributed Component Object Model (DCOM) enables software components to communicate over a network, often used in Windows environments for remote management. Adversaries exploit DCOM to execute commands remotely, leveraging applications like MMC20 to move laterally. The detection rule identifies suspicious activity by monitoring network traffic and process creation patterns, flagging potential misuse when MMC initiates remote commands, indicating possible lateral movement or defense evasion tactics.

**Possible investigation steps**

* Review the network traffic logs to identify the source IP address that initiated the connection to the host running mmc.exe. Verify if this IP address is known and expected within the network environment.
* Examine the process creation logs to confirm the parent-child relationship between mmc.exe and any suspicious processes. Investigate the child processes for any unusual or unauthorized activities.
* Check the source and destination ports (both should be >= 49152) involved in the network connection to determine if they align with typical application behavior or if they are indicative of potential misuse.
* Investigate the timeline of events to see if there are any other related alerts or activities on the same host or originating from the same source IP address, which could provide additional context or indicate a broader attack pattern.
* Correlate the findings with any existing threat intelligence or known attack patterns related to DCOM abuse and lateral movement to assess the potential risk and impact on the organization.

**False positive analysis**

* Legitimate administrative tasks using MMC may trigger the rule. Regularly review and document routine administrative activities to differentiate them from suspicious behavior.
* Automated scripts or management tools that use MMC for remote management can cause false positives. Identify and whitelist these tools by their process and network patterns.
* Internal network scanning or monitoring tools might mimic the behavior detected by the rule. Exclude known IP addresses or ranges associated with these tools to reduce noise.
* Scheduled tasks or maintenance operations that involve MMC could be misinterpreted as lateral movement. Ensure these tasks are logged and recognized as part of normal operations.
* Software updates or patches that require MMC to execute remote commands might trigger alerts. Maintain an updated list of such activities and exclude them from triggering the rule.

**Response and remediation**

* Isolate the affected host immediately from the network to prevent further lateral movement and contain the threat.
* Terminate any suspicious processes associated with mmc.exe on the affected host to stop any ongoing malicious activity.
* Conduct a thorough review of the affected host’s event logs and network traffic to identify any additional indicators of compromise or other affected systems.
* Reset credentials for any accounts that were accessed or potentially compromised during the incident to prevent unauthorized access.
* Apply patches and updates to the affected systems and any other vulnerable systems in the network to mitigate known vulnerabilities that could be exploited.
* Implement network segmentation to limit the ability of threats to move laterally within the network in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional actions are necessary.


## Rule query [_rule_query_459]

```js
sequence by host.id with maxspan=1m
 [network where host.os.type == "windows" and event.type == "start" and process.name : "mmc.exe" and source.port >= 49152 and
 destination.port >= 49152 and source.ip != "127.0.0.1" and source.ip != "::1" and
  network.direction : ("incoming", "ingress") and network.transport == "tcp"
 ] by process.entity_id
 [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "mmc.exe"
 ] by process.parent.entity_id
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

* Sub-technique:

    * Name: Distributed Component Object Model
    * ID: T1021.003
    * Reference URL: [https://attack.mitre.org/techniques/T1021/003/](https://attack.mitre.org/techniques/T1021/003/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: MMC
    * ID: T1218.014
    * Reference URL: [https://attack.mitre.org/techniques/T1218/014/](https://attack.mitre.org/techniques/T1218/014/)



