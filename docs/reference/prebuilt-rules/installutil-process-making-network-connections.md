---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/installutil-process-making-network-connections.html
---

# InstallUtil Process Making Network Connections [installutil-process-making-network-connections]

Identifies InstallUtil.exe making outbound network connections. This may indicate adversarial activity as InstallUtil is often leveraged by adversaries to execute code and evade detection.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.network-*
* winlogbeat-*
* logs-windows.sysmon_operational-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_434]

**Triage and analysis**

[TBC: QUOTE]
**Investigating InstallUtil Process Making Network Connections**

InstallUtil.exe is a legitimate Windows utility used for installing and uninstalling server resources by executing installer components. Adversaries exploit it to run malicious code under the guise of legitimate processes, often to evade detection. The detection rule identifies suspicious network activity by monitoring InstallUtil.exe’s outbound connections, flagging potential misuse by alerting on the initial network connection attempt.

**Possible investigation steps**

* Review the alert details to confirm the process.entity_id and ensure it matches the InstallUtil.exe process making the outbound network connection.
* Investigate the destination IP address and port of the network connection to determine if it is known, trusted, or associated with malicious activity.
* Examine the parent process of InstallUtil.exe to identify how it was launched and assess if this behavior is expected or potentially malicious.
* Check the timeline of events around the process start and network connection to identify any other suspicious activities or related processes.
* Look for any additional network connections made by the same process.entity_id to assess if there is a pattern or further evidence of malicious behavior.
* Review system logs and security alerts for any other indicators of compromise or related suspicious activities on the host.

**False positive analysis**

* Legitimate software installations or updates may trigger InstallUtil.exe to make network connections. Users can create exceptions for known software update processes by identifying their specific process entity IDs and excluding them from the alert.
* System administrators may use InstallUtil.exe for routine maintenance tasks that require network access. To prevent false positives, document these tasks and configure the detection rule to exclude these specific instances.
* Automated deployment tools that utilize InstallUtil.exe for legitimate purposes can be a source of false positives. Identify these tools and their associated network activities, then adjust the rule to ignore these benign connections.
* Development environments where InstallUtil.exe is used for testing purposes might generate alerts. Establish a list of development machines and exclude their process entity IDs from the detection rule to reduce noise.
* Scheduled tasks or scripts that use InstallUtil.exe for legitimate network operations should be reviewed. Once verified as non-threatening, these can be added to an exception list to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further malicious activity and potential lateral movement.
* Terminate the InstallUtil.exe process on the affected system to stop any ongoing malicious actions.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious payloads or associated files.
* Review and analyze the network logs to identify any other systems that may have been contacted by the malicious process and assess if they are compromised.
* Restore the affected system from a known good backup if malicious activity is confirmed and cannot be fully remediated.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement network monitoring and alerting for unusual outbound connections from critical systems to enhance detection of similar threats in the future.


## Rule query [_rule_query_469]

```js
/* the benefit of doing this as an eql sequence vs kql is this will limit to alerting only on the first network connection */

sequence by process.entity_id
  [process where host.os.type == "windows" and event.type == "start" and process.name : "installutil.exe"]
  [network where host.os.type == "windows" and process.name : "installutil.exe" and network.direction : ("outgoing", "egress")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: InstallUtil
    * ID: T1218.004
    * Reference URL: [https://attack.mitre.org/techniques/T1218/004/](https://attack.mitre.org/techniques/T1218/004/)



