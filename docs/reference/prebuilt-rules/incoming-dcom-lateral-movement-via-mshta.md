---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/incoming-dcom-lateral-movement-via-mshta.html
---

# Incoming DCOM Lateral Movement via MSHTA [incoming-dcom-lateral-movement-via-mshta]

Identifies the use of Distributed Component Object Model (DCOM) to execute commands from a remote host, which are launched via the HTA Application COM Object. This behavior may indicate an attacker abusing a DCOM application to move laterally while attempting to evade detection.

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

* [https://codewhitesec.blogspot.com/2018/07/lethalhta.html](https://codewhitesec.blogspot.com/2018/07/lethalhta.md)

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

## Investigation guide [_investigation_guide_425]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Incoming DCOM Lateral Movement via MSHTA**

DCOM allows software components to communicate over a network, enabling remote execution of applications like MSHTA, which runs HTML applications. Adversaries exploit this by executing commands remotely, bypassing traditional security measures. The detection rule identifies suspicious MSHTA activity by monitoring process starts and network traffic, focusing on unusual port usage and remote IP addresses, indicating potential lateral movement attempts.

**Possible investigation steps**

* Review the process start event for mshta.exe on the affected host to gather details such as the process entity ID, command-line arguments, and parent process information to understand how mshta.exe was executed.
* Analyze the network traffic associated with the mshta.exe process, focusing on the source and destination IP addresses and ports, to identify any unusual or unauthorized remote connections.
* Check the source IP address involved in the network event to determine if it is known or associated with any previous suspicious activity or if it belongs to an internal or external network.
* Investigate the timeline of events on the host to identify any preceding or subsequent suspicious activities that might indicate a broader attack pattern or lateral movement attempts.
* Correlate the findings with other security logs and alerts from the same host or network segment to identify any additional indicators of compromise or related malicious activities.
* Assess the risk and impact of the detected activity by considering the host’s role within the network and any sensitive data or systems it may have access to.

**False positive analysis**

* Legitimate administrative tasks using MSHTA for remote management can trigger the rule. Identify and document these tasks, then create exceptions for known administrative IP addresses or specific user accounts.
* Automated software updates or deployments that utilize MSHTA may appear as suspicious activity. Monitor and whitelist the IP addresses and ports associated with these updates to prevent false positives.
* Internal network scanning tools or security assessments might mimic lateral movement behavior. Coordinate with IT and security teams to recognize these activities and exclude them from triggering alerts.
* Custom applications that leverage MSHTA for inter-process communication could be flagged. Review these applications and exclude their known processes or network patterns from the detection rule.
* Remote desktop or support tools that use MSHTA for legitimate purposes should be identified. Whitelist these tools by their process names or associated network traffic to reduce unnecessary alerts.

**Response and remediation**

* Isolate the affected host immediately from the network to prevent further lateral movement and potential data exfiltration.
* Terminate the mshta.exe process on the affected host to stop any ongoing malicious activity.
* Conduct a thorough examination of the affected host to identify any additional malicious files or processes, focusing on those initiated around the time of the alert.
* Reset credentials for any accounts that were active on the affected host during the time of the alert to prevent unauthorized access.
* Review and restrict DCOM permissions and configurations on the affected host and other critical systems to limit the potential for similar attacks.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other systems have been compromised.
* Update detection mechanisms and threat intelligence feeds to enhance monitoring for similar DCOM-based lateral movement attempts in the future.


## Rule query [_rule_query_458]

```js
sequence with maxspan=1m
  [process where host.os.type == "windows" and event.type == "start" and
     process.name : "mshta.exe" and process.args : "-Embedding"
  ] by host.id, process.entity_id
  [network where host.os.type == "windows" and event.type == "start" and process.name : "mshta.exe" and
     network.direction : ("incoming", "ingress") and network.transport == "tcp" and
     source.port > 49151 and destination.port > 49151 and source.ip != "127.0.0.1" and source.ip != "::1"
  ] by host.id, process.entity_id
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

    * Name: Mshta
    * ID: T1218.005
    * Reference URL: [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)



